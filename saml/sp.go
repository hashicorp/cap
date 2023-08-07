package saml

import (
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

var ErrBindingUnsupported = errors.New("Configured binding unsupported by the IDP")

//go:embed post_binding.gohtml
var PostBindingTempl string

type ServiceProvider struct {
	cfg *Config
}

// NewServiceProvider creates a new ServiceProvider.
func NewServiceProvider(cfg *Config) (*ServiceProvider, error) {
	const op = "saml.NewServiceProvider"

	if cfg == nil {
		return nil, fmt.Errorf(
			"%s: no provider config provided",
			op,
		)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf(
			"%s: insufficient provider config: %w",
			op, err,
		)
	}

	return &ServiceProvider{
		cfg: cfg,
	}, nil
}

// Config returns the service provider config.
func (sp *ServiceProvider) Config() *Config {
	return sp.cfg
}

// CreateAuthNRequest creates an Authentication Request object. If no service binding defined in the
// config it defaults to the HTTP POST binding.
func (sp *ServiceProvider) CreateAuthnRequest(
	id string,
	binding core.ServiceBinding,
) (*core.AuthnRequest, error) {
	const op = "saml.ServiceProvider.CreateAuthnRequest"

	if id == "" {
		return nil, fmt.Errorf("%s: no ID provided: %w", op, oidc.ErrInvalidParameter)
	}

	if binding == "" {
		return nil, fmt.Errorf("%s: no binding provided: %w", op, oidc.ErrInvalidParameter)
	}

	destination, err := sp.destination(binding)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: failed to get destination for given service binding (%s): %w",
			op,
			binding,
			err,
		)
	}

	ar := &core.AuthnRequest{}

	ar.ID = id
	ar.Version = core.SAMLVersion2
	ar.ProtocolBinding = core.ServiceBindingHTTPPost
	ar.AssertionConsumerServiceURL = sp.cfg.AssertionConsumerServiceURL.String()
	ar.IssueInstant = time.Now().UTC() // TODO format this.
	ar.Destination = destination

	ar.Issuer = &core.Issuer{}
	ar.Issuer.Value = sp.cfg.EntityID.String()

	ar.NameIDPolicy = &core.NameIDPolicy{
		AllowCreate: false,                  // TODO: Create option
		Format:      core.NameIDFormatEmail, // TODO: Create option
	}

	ar.ForceAuthn = false // TODO: Create Option

	return ar, nil
}

func (sp *ServiceProvider) CreateMetadata() *metadata.EntityDescriptorSPSSO {
	validUntil := sp.cfg.ValidUntil()

	spsso := metadata.EntityDescriptorSPSSO{}
	spsso.EntityID = sp.cfg.EntityID.String()
	spsso.ValidUntil = validUntil

	spssoDescriptor := &metadata.SPSSODescriptor{}
	spssoDescriptor.ValidUntil = validUntil
	spssoDescriptor.ProtocolSupportEnumeration = metadata.ProtocolSupportEnumerationProtocol
	spssoDescriptor.NameIDFormat = []core.NameIDFormat{
		core.NameIDFormatEmail,
		core.NameIDFormatTransient,
	}
	spssoDescriptor.AuthnRequestsSigned = false // TODO: create option for this
	spssoDescriptor.WantAssertionsSigned = true // TODO: create option for this
	spssoDescriptor.AssertionConsumerService = []metadata.IndexedEndpoint{
		{
			Endpoint: metadata.Endpoint{
				Binding:  core.ServiceBindingHTTPPost,
				Location: sp.cfg.AssertionConsumerServiceURL.String(),
			},
			Index: 1,
		},
	}

	spsso.SPSSODescriptor = []*metadata.SPSSODescriptor{spssoDescriptor}

	return &spsso
}

// FetchMetadata fetches the metadata XML document from the IDP provider.
func (sp *ServiceProvider) FetchMetadata() (*metadata.EntityDescriptorIDPSSO, error) {
	const op = "saml.ServiceProvider.FetchMetdata"

	if sp.cfg.MetadataURL == nil {
		return nil, fmt.Errorf("%s: no metadata URL set: %w", op, oidc.ErrInvalidParameter)
	}

	res, err := http.Get(sp.cfg.MetadataURL.String())
	if err != nil {
		return nil, fmt.Errorf("%s: failed to fetch metadata: %w", op, err)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read http body: %w", op, err)
	}

	var ed metadata.EntityDescriptorIDPSSO
	err = xml.Unmarshal(raw, &ed)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse metadata XML: %w", op, err)
	}

	return &ed, nil
}

func (sp *ServiceProvider) destination(binding core.ServiceBinding) (string, error) {
	const op = "saml.ServiceProvider.destination"

	meta, err := sp.FetchMetadata()
	if err != nil {
		return "", fmt.Errorf("%s: failed to fetch metadata: %w", op, err)
	}

	destination, ok := meta.GetLocationForBinding(binding)
	if !ok {
		return "", fmt.Errorf(
			"%s: no location for provided binding (%s) found: %w",
			op, binding, ErrBindingUnsupported,
		)
	}

	return destination, nil
}
