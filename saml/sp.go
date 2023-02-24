package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

var (
	ErrBindingUnsupported = errors.New("Configured binding unsupported by the IDP")
)

type ServiceProvider struct {
	cfg *Config
}

func NewServiceProvider(cfg *Config) (*ServiceProvider, error) {
	const op = "saml.NewServiceProvider"

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf(
			"%s: can't create new service provider with insufficient configuration: %w",
			op, err,
		)
	}

	return &ServiceProvider{
		cfg: cfg,
	}, nil
}

// CreateAuthNRequest creates an Authentication Request object. If no service binding defined in the
// config it defaults to the HTTP POST binding.
func (sp *ServiceProvider) CreateAuthNRequest(id string) (*core.AuthnRequest, error) {
	const op = "saml.ServiceProvider.CreateAuthNRequest"

	if id == "" {
		return nil, fmt.Errorf("%s: id is empty: %w", op, oidc.ErrInvalidParameter)
	}

	destination, err := sp.destination()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get destination: %w", op, err)
	}

	ar := &core.AuthnRequest{}

	ar.ID = id
	ar.Version = core.SAMLVersion2
	ar.ProtocolBinding = sp.cfg.ServiceBinding
	ar.AssertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL
	ar.IssueInstant = time.Now().UTC() // TODO format this.
	ar.Destination = destination

	ar.Issuer = &core.Issuer{}
	ar.Issuer.Value = sp.cfg.EntityID

	ar.NameIDPolicy = &core.NameIDPolicy{
		AllowCreate: true,
		Format:      sp.cfg.NameIDFormat,
	}

	if sp.cfg.NameIDFormat == "" {
		ar.NameIDPolicy.Format = core.NameIDFormatEmail
	}

	ar.ForceAuthn = false

	// TODO: RequestedAuthnContext?
	// TODO: Sign request

	return ar, nil
}

func (sp *ServiceProvider) CreateSPMetadata() *metadata.EntityDescriptorSPSSO {
	validUntil := sp.cfg.ValidUntil()

	spsso := metadata.EntityDescriptorSPSSO{}
	spsso.EntityID = sp.cfg.EntityID
	spsso.ValidUntil = validUntil

	spssoDescriptor := &metadata.SPSSODescriptor{}
	spssoDescriptor.ValidUntil = validUntil
	spssoDescriptor.ProtocolSupportEnumeration = metadata.ProtocolSupportEnumerationProtocol
	spssoDescriptor.NameIDFormat = []core.NameIDFormat{core.NameIDFormatEmail, core.NameIDFormatTransient}
	spssoDescriptor.AuthnRequestsSigned = false
	spssoDescriptor.WantAssertionsSigned = false
	spssoDescriptor.AssertionConsumerService = []metadata.IndexedEndpoint{
		{
			Endpoint: metadata.Endpoint{
				Binding:  core.ServiceBindingHTTPPost,
				Location: sp.cfg.AssertionConsumerServiceURL,
			},
			Index: 1,
		},
	}

	spsso.SPSSODescriptor = []*metadata.SPSSODescriptor{spssoDescriptor}

	return &spsso
}

func (sp *ServiceProvider) FetchMetadata() (*metadata.EntityDescriptorIDPSSO, error) {
	const op = "saml.ServiceProvider.FetchMetdata"

	if sp.cfg.MetadataURL == "" {
		return nil, fmt.Errorf("%s: no metadata url set: %w", op, oidc.ErrInvalidParameter)
	}

	res, err := http.Get(sp.cfg.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to fetch metadata: %w", op, err)
	}

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read body: %w", op, err)
	}

	var ed metadata.EntityDescriptorIDPSSO
	err = xml.Unmarshal(raw, &ed)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal metadata XML document: %w", op, err)
	}

	return &ed, nil
}

func (sp *ServiceProvider) ServiceBinding() core.ServiceBinding {
	return sp.cfg.ServiceBinding
}

func (sp *ServiceProvider) destination() (string, error) {
	const op = "saml.ServiceProvider.destination"

	if sp.cfg.IDP != nil {
		return sp.cfg.IDP.SSOServiceURL, nil
	}

	meta, err := sp.FetchMetadata()
	if err != nil {
		return "", fmt.Errorf("%s: failed to fetch metadata: %w", op, err)
	}

	destination, ok := meta.GetLocationForBinding(sp.cfg.ServiceBinding)
	if !ok {
		return "", fmt.Errorf(
			"%s: no location for provided binding (%s) found: %w",
			op, sp.cfg.ServiceBinding, ErrBindingUnsupported,
		)
	}

	return destination, nil
}
