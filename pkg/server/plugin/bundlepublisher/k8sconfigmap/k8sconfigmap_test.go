package k8sconfigmap

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest *configv1.ConfigureRequest
		newClientErr     error
		expectCode       codes.Code
		expectMsg        string
		config           *Config
	}{
		{
			name: "success",
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
		},
		{
			name: "success with kubeconfig",
			config: &Config{
				Namespace:      "spire",
				ConfigMapName:  "spire-bundle",
				ConfigMapKey:   "bundle.json",
				Format:         "spiffe",
				KubeConfigPath: "/path/to/kubeconfig",
			},
		},
		{
			name: "no namespace",
			config: &Config{
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the namespace",
		},
		{
			name: "no configmap name",
			config: &Config{
				Namespace:    "spire",
				ConfigMapKey: "bundle.json",
				Format:       "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the configmap name",
		},
		{
			name: "no configmap key",
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				Format:        "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the configmap key",
		},
		{
			name: "no bundle format",
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the bundle format",
		},
		{
			name: "client error",
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
			expectCode:   codes.Internal,
			expectMsg:    "failed to create Kubernetes client: client creation error",
			newClientErr: errors.New("client creation error"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(config *Config) (kubernetesClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{}, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration
			tt.config.bundleFormat, err = bundleformat.FromString(tt.config.Format)
			require.NoError(t, err)
			require.Equal(t, tt.config, p.config)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		newClientErr       error
		expectCode         codes.Code
		expectMsg          string
		config             *Config
		bundle             *types.Bundle
		getConfigMapErr    error
		createConfigMapErr error
		updateConfigMapErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
		},
		{
			name:   "get configmap failure",
			bundle: testBundle,
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
			getConfigMapErr: errors.New("get error"),
			expectCode:      codes.Internal,
			expectMsg:       "failed to get ConfigMap: get error",
		},
		{
			name:   "update configmap failure",
			bundle: testBundle,
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
			updateConfigMapErr: errors.New("update error"),
			expectCode:         codes.Internal,
			expectMsg:          "failed to update ConfigMap: update error",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				Namespace:     "spire",
				ConfigMapName: "spire-bundle",
				ConfigMapKey:  "bundle.json",
				Format:        "spiffe",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(config *Config) (kubernetesClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{
					t:                  t,
					expectNamespace:    tt.config.Namespace,
					expectName:         tt.config.ConfigMapName,
					expectKey:          tt.config.ConfigMapKey,
					getConfigMapErr:    tt.getConfigMapErr,
					updateConfigMapErr: tt.updateConfigMapErr,
				}, nil
			}
			p := newPlugin(newClient)

			if tt.config != nil {
				plugintest.Load(t, builtin(p), nil, options...)
				require.NoError(t, err)
			}

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	config := &Config{
		Namespace:     "spire",
		ConfigMapName: "spire-bundle",
		ConfigMapKey:  "bundle.json",
		Format:        "spiffe",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	client := &fakeClient{
		t:               t,
		expectNamespace: config.Namespace,
		expectName:      config.ConfigMapName,
		expectKey:       config.ConfigMapKey,
	}

	newClientFunc := func(c *Config) (kubernetesClient, error) {
		return client, nil
	}

	p := newPlugin(newClientFunc)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple update operations, and check that only a call to update ConfigMap is
	// done when there is a modified bundle that was not successfully published before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	// Reset the update counter.
	client.updateCount = 0
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.updateCount)

	// Call PublishBundle with the same bundle.
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the updateCount counter should be still 1.
	require.Equal(t, 1, client.updateCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, updateCount should
	// be incremented to be 2.
	require.Equal(t, 2, client.updateCount)

	// Simulate that updating ConfigMap fails with an error.
	client.updateConfigMapErr = errors.New("error updating ConfigMap")

	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	// Since there is no change in the bundle, Update should not be called
	// and there should be no error.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the updateCount counter should be still 2.
	require.Equal(t, 2, client.updateCount)

	// Have a new bundle and call PublishBundle. Update should be called this
	// time and return an error.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 3
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Since the bundle could not be published, updateCount should be
	// still 2.
	require.Equal(t, 2, client.updateCount)

	// Clear the update error and call PublishBundle.
	client.updateConfigMapErr = nil
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})

	// No error should happen this time.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The updateCount counter should be incremented to 3, since the bundle
	// should have been published successfully.
	require.Equal(t, 3, client.updateCount)
}

type fakeClient struct {
	t *testing.T

	expectNamespace    string
	expectName         string
	expectKey          string
	getConfigMapErr    error
	updateConfigMapErr error
	updateCount        int
}

func (c *fakeClient) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	if c.getConfigMapErr != nil {
		return nil, c.getConfigMapErr
	}
	require.Equal(c.t, c.expectNamespace, namespace, "namespace mismatch")
	require.Equal(c.t, c.expectName, name, "configmap name mismatch")

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string]string{},
	}, nil
}

func (c *fakeClient) UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	if c.updateConfigMapErr != nil {
		return c.updateConfigMapErr
	}

	require.Equal(c.t, c.expectNamespace, configMap.Namespace, "namespace mismatch")
	require.Equal(c.t, c.expectName, configMap.Name, "configmap name mismatch")
	require.Contains(c.t, configMap.Data, c.expectKey, "configmap key missing")

	c.updateCount++
	return nil
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
