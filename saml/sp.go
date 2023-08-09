package saml

import (
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/cap/oidc"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

var ErrBindingUnsupported = errors.New("Configured binding unsupported by the IDP")

//go:embed authn_request.gohtml
var PostBindingTempl string

type metadataOptions struct {
	wantAssertionsSigned bool
	nameIDFormats        []core.NameIDFormat
	acsServiceBinding    core.ServiceBinding
	addtionalACSs        []metadata.Endpoint
}

func metadataOptionsDefault() metadataOptions {
	return metadataOptions{
		wantAssertionsSigned: true,
		nameIDFormats: []core.NameIDFormat{
			core.NameIDFormatEmail,
		},
		acsServiceBinding: core.ServiceBindingHTTPPost,
	}
}

func getMetadataOptions(opt ...Option) metadataOptions {
	opts := metadataOptionsDefault()
	ApplyOpts(&opts, opt...)
	return opts
}

func InsecureWantAssertionsUnsigned() Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.wantAssertionsSigned = false
		}
	}
}

func WithAdditionalNameIDFormat(format core.NameIDFormat) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.nameIDFormats = append(o.nameIDFormats, format)
		}
	}
}

func WithNameIDFormats(formats []core.NameIDFormat) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.nameIDFormats = formats
		}
	}
}

func WithACSServiceBinding(b core.ServiceBinding) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.acsServiceBinding = b
		}
	}
}

func WithAdditionalACSEndpoint(b core.ServiceBinding, location *url.URL) Option {
	return func(o interface{}) {
		if o, ok := o.(*metadataOptions); ok {
			o.addtionalACSs = append(o.addtionalACSs, metadata.Endpoint{
				Binding:  b,
				Location: location.String(),
			})
		}
	}
}

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

// CreateMetadata creates the metadata XML for the service provider.
//
// Options:
// - InsecureWantAssertionsUnsigned
// - WithNameIDFormats
// - WithACSServiceBinding
// - WithAdditonalACSEndpoint
func (sp *ServiceProvider) CreateMetadata(opt ...Option) *metadata.EntityDescriptorSPSSO {
	validUntil := sp.cfg.ValidUntil()

	opts := getMetadataOptions(opt...)

	spsso := metadata.EntityDescriptorSPSSO{}
	spsso.EntityID = sp.cfg.EntityID.String()
	spsso.ValidUntil = validUntil

	spssoDescriptor := &metadata.SPSSODescriptor{}
	spssoDescriptor.ValidUntil = validUntil
	spssoDescriptor.ProtocolSupportEnumeration = metadata.ProtocolSupportEnumerationProtocol
	spssoDescriptor.NameIDFormat = opts.nameIDFormats
	spssoDescriptor.AuthnRequestsSigned = false // always false for now until request signing is supported.
	spssoDescriptor.WantAssertionsSigned = opts.wantAssertionsSigned
	spssoDescriptor.AssertionConsumerService = []metadata.IndexedEndpoint{
		{
			Endpoint: metadata.Endpoint{
				Binding:  opts.acsServiceBinding,
				Location: sp.cfg.AssertionConsumerServiceURL.String(),
			},
			Index: 1,
		},
	}

	for i, a := range opts.addtionalACSs {
		spssoDescriptor.AssertionConsumerService = append(
			spssoDescriptor.AssertionConsumerService,
			metadata.IndexedEndpoint{
				Endpoint: a,
				Index:    i + 2, // The first index is already taken.
			},
		)
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

	// [SDP-MD03] https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_metadata_and_trust_management
	// Metadata without a validUntil attribute on its root element MUST be rejected. Metadata whose root element’s validUntil
	// attribute extends beyond a deployer- or community-imposed threshold MUST be rejected.
	// TODO: VALIDATE

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
