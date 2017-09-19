package node

import (
	"context"
	"errors"
	"fmt"

	"reflect"
	"sort"

	"github.com/sirupsen/logrus"
	pb "github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
	"github.com/spiffe/spire/services"
)

// Service is the interface that provides node api methods.
type Service interface {
	FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error)
	FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse, err error)
	FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse, err error)
	FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse, err error)
}

type service struct {
	l               logrus.FieldLogger
	attestation     services.Attestation
	identity        services.Identity
	ca              services.CA
	registration    services.Registration
	baseSpiffeIDTTL int32
	dataStore       datastore.DataStore
	serverCA        ca.ControlPlaneCa
}

//Config is a configuration struct to init the service
type Config struct {
	logger          logrus.FieldLogger
	Attestation     services.Attestation
	Identity        services.Identity
	CA              services.CA
	Registration    services.Registration
	DataStore       datastore.DataStore
	ServerCA        ca.ControlPlaneCa
	BaseSpiffeIDTTL int32
}

// NewService creates a node service with the necessary dependencies.
func NewService(config Config) (s Service) {
	//TODO: validate config?
	return &service{
		l:               config.logger,
		attestation:     config.Attestation,
		identity:        config.Identity,
		registration:    config.Registration,
		ca:              config.CA,
		baseSpiffeIDTTL: config.BaseSpiffeIDTTL,
		dataStore:       config.DataStore,
		serverCA:        config.ServerCA,
	}
}

//TODO: log errors
//FetchBaseSVID attests the node and gets the base node SVID.
func (no *service) FetchBaseSVID(ctx context.Context, request pb.FetchBaseSVIDRequest) (response pb.FetchBaseSVIDResponse, err error) {
	//Attest the node and get baseSpiffeID
	baseSpiffeIDFromCSR, err := no.ca.GetSpiffeIDFromCSR(request.Csr)
	if err != nil {
		return response, err
	}

	attestedBefore, err := no.attestation.IsAttested(baseSpiffeIDFromCSR)
	if err != nil {
		return response, err
	}

	var attestResponse *nodeattestor.AttestResponse
	attestResponse, err = no.attestation.Attest(request.AttestedData, attestedBefore)
	if err != nil {
		return response, err
	}

	//Validate
	if !attestResponse.Valid {
		return response, errors.New("Invalid")
	}

	//check if baseSPIFFEID in attest response matches with SPIFFEID in CSR
	if attestResponse.BaseSPIFFEID != baseSpiffeIDFromCSR {
		return response, errors.New("BaseSPIFFEID MisMatch")
	}

	//Sign csr
	var signCsrResponse *ca.SignCsrResponse
	if signCsrResponse, err = no.ca.SignCsr(&ca.SignCsrRequest{Csr: request.Csr}); err != nil {
		return response, err
	}

	baseSpiffeID := attestResponse.BaseSPIFFEID
	if attestedBefore {
		//UPDATE attested node entry
		if err = no.attestation.UpdateEntry(baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			return response, err
		}

	} else {
		//CREATE attested node entry
		if err = no.attestation.CreateEntry(request.AttestedData.Type, baseSpiffeID, signCsrResponse.SignedCertificate); err != nil {
			return response, err
		}
	}

	//Call node resolver plugin to get a map of {Spiffe ID,[ ]Selector}
	var selectors map[string]*common.Selectors
	if selectors, err = no.identity.Resolve([]string{baseSpiffeID}); err != nil {
		return response, err
	}

	baseIDSelectors, ok := selectors[baseSpiffeID]
	//generateCombination(baseIDSelectors) (TODO:walmav)
	var selectorEntries []*common.Selector
	if ok {
		selectorEntries = baseIDSelectors.Entries
		for _, selector := range selectorEntries {
			if err = no.identity.CreateEntry(baseSpiffeID, selector); err != nil {
				return response, err
			}
		}
	}

	svids := make(map[string]*pb.Svid)
	svids[baseSpiffeID] = &pb.Svid{SvidCert: signCsrResponse.SignedCertificate, Ttl: no.baseSpiffeIDTTL}

	regEntries, err := no.fetchRegistrationEntries(selectorEntries, baseSpiffeID)
	svidUpdate := &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	response = pb.FetchBaseSVIDResponse{SvidUpdate: svidUpdate}

	return response, nil
}

//FetchSVID gets Workload, Agent certs and CA trust bundles.
//Also used for rotation Base Node SVID or the Registered Node SVID used for this call.
//List can be empty to allow Node Agent cache refresh).
func (no *service) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse, err error) {
	//TODO: rename no to s
	//TODO: extract this from the caller cert
	baseSpiffeID := "spiffe://example.org/spiffe/node-id/token"

	req := &datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}
	nodeResolutionResponse, err := no.dataStore.FetchNodeResolverMapEntry(req)
	if err != nil {
		return response, fmt.Errorf("Error trying to FetchNodeResolverMapEntry")
	}
	selectors := convertToSelectors(nodeResolutionResponse.NodeResolverMapEntryList)

	regEntries, err := no.fetchRegistrationEntries(selectors, baseSpiffeID)
	if err != nil {
		no.l.Error(err)
		return response, fmt.Errorf("Error trying to fetchRegistrationEntries")
	}

	//convert registration entries to map for easy lookup
	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.SpiffeId] = entry
	}

	//iterate CSRs, validate them and sign the certificates
	svids := make(map[string]*pb.Svid)
	for _, csr := range request.Csrs {
		spiffeID, err := no.ca.GetSpiffeIDFromCSR(csr)
		if err != nil {
			no.l.Error(err)
			return response, fmt.Errorf("Error trying to get SpiffeId from CSR")
		}

		//TODO: Validate that other fields are not populated https://github.com/spiffe/spire/issues/161
		//validate that is present in the registration entries, otherwise we shouldn't sign
		entry, ok := regEntriesMap[spiffeID]
		if !ok {
			err := fmt.Errorf("Not entitled to sign CSR")
			no.l.Error(err)
			return response, err
		}

		//sign
		signReq := &ca.SignCsrRequest{Csr: csr}
		res, err := no.serverCA.SignCsr(signReq)
		if err != nil {
			no.l.Error(err)
			return response, fmt.Errorf("Error trying to sign CSR")
		}
		svids[spiffeID] = &pb.Svid{SvidCert: res.SignedCertificate, Ttl: entry.Ttl}
	}

	response.SvidUpdate = &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: regEntries,
	}
	return response, nil
}

// Implement the business logic of FetchCPBundle
func (no *service) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse, err error) {
	return response, nil
}

// Implement the business logic of FetchFederatedBundle
func (no *service) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse, err error) {
	return response, nil
}

func convertToSelectors(resolution []*datastore.NodeResolverMapEntry) []*common.Selector {
	var selectors []*common.Selector
	for _, item := range resolution {
		selectors = append(selectors, item.Selector)
	}
	return selectors
}

func (no *service) fetchRegistrationEntries(selectors []*common.Selector, spiffeID string) (
	[]*common.RegistrationEntry, error) {
	///lookup Registration Entries for resolved selectors
	var entries []*common.RegistrationEntry
	var selectorsEntries []*common.RegistrationEntry

	for _, selector := range selectors {
		listSelectorResponse, err := no.dataStore.ListSelectorEntries(&datastore.ListSelectorEntriesRequest{Selector: selector})
		if err != nil {
			return nil, err
		}
		selectorsEntries = append(selectorsEntries, listSelectorResponse.RegisteredEntryList...)
	}
	entries = append(entries, selectorsEntries...)

	///lookup Registration Entries where spiffeID is the parent ID
	listResponse, err := no.dataStore.ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: spiffeID})
	if err != nil {
		return nil, err
	}
	///append parentEntries
	for _, entry := range listResponse.RegisteredEntryList {
		exists := false
		sort.Slice(entry.Selectors, util.SelectorsSortFunction(entry.Selectors))
		for _, oldEntry := range selectorsEntries {
			sort.Slice(oldEntry.Selectors, util.SelectorsSortFunction(oldEntry.Selectors))
			if reflect.DeepEqual(entry, oldEntry) {
				exists = true
			}
		}
		if !exists {
			entries = append(entries, entry)
		}
	}
	return entries, err
}
