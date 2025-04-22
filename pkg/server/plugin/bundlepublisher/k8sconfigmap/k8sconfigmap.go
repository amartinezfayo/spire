package k8sconfigmap

import (
	"context"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "k8s_configmap"
)

type pluginHooks struct {
	newK8sClientFunc func(config *Config) (kubernetesClient, error)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func New() *Plugin {
	return newPlugin(newK8sClient)
}

// Config holds the configuration of the plugin.
type Config struct {
	Namespace      string `hcl:"namespace" json:"namespace"`
	ConfigMapName  string `hcl:"configmap_name" json:"configmap_name"`
	ConfigMapKey   string `hcl:"configmap_key" json:"configmap_key"`
	Format         string `hcl:"format" json:"format"`
	KubeConfigPath string `hcl:"kubeconfig_path" json:"kubeconfig_path"`

	// bundleFormat is used to store the content of Format, parsed
	// as bundleformat.Format.
	bundleFormat bundleformat.Format
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.Namespace == "" {
		status.ReportError("configuration is missing the namespace")
	}
	if newConfig.ConfigMapName == "" {
		status.ReportError("configuration is missing the configmap name")
	}
	if newConfig.ConfigMapKey == "" {
		status.ReportError("configuration is missing the configmap key")
	}
	if newConfig.Format == "" {
		status.ReportError("configuration is missing the bundle format")
	}

	bundleFormat, err := bundleformat.FromString(newConfig.Format)
	if err != nil {
		status.ReportErrorf("could not parse bundle format from configuration: %v", err)
	} else {
		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("bundle format %q is not supported", newConfig.Format)
		}
		newConfig.bundleFormat = bundleFormat
	}

	return newConfig
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config    *Config
	configMtx sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	hooks     pluginHooks
	k8sClient kubernetesClient
	log       hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	k8sClient, err := p.hooks.newK8sClientFunc(newConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Kubernetes client: %v", err)
	}
	p.k8sClient = k8sClient

	p.setConfig(newConfig)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

// PublishBundle puts the bundle in the configured Kubernetes ConfigMap.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	formatter := bundleformat.NewFormatter(req.Bundle)
	bundleBytes, err := formatter.Format(config.bundleFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err.Error())
	}

	cm, err := p.k8sClient.GetConfigMap(ctx, config.Namespace, config.ConfigMapName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get ConfigMap: %v", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[config.ConfigMapKey] = string(bundleBytes)

	err = p.k8sClient.UpdateConfigMap(ctx, cm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update ConfigMap: %v", err)
	}

	p.setBundle(req.Bundle)
	p.log.Debug("Bundle published to Kubernetes ConfigMap",
		"namespace", config.Namespace,
		"configmap", config.ConfigMapName,
		"key", config.ConfigMapKey)
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()

	return p.bundle
}

// getConfig gets the configuration of the plugin.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

// setConfig sets the configuration for the plugin.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()

	p.config = config
}

// builtin creates a new BundlePublisher built-in plugin.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		bundlepublisherv1.BundlePublisherPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// newPlugin returns a new plugin instance.
func newPlugin(newK8sClientFunc func(c *Config) (kubernetesClient, error)) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newK8sClientFunc: newK8sClientFunc,
		},
	}
}
