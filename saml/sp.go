package saml

import (
	_ "embed"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
	dsig "github.com/russellhaering/goxmldsig/types"
)

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
	spsso.EntityID = sp.cfg.EntityID
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
				Location: sp.cfg.AssertionConsumerServiceURL,
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

// IDPMetadata fetches the metadata XML document from the configured identity provider.
func (sp *ServiceProvider) IDPMetadata() (*metadata.EntityDescriptorIDPSSO, error) {
	const op = "saml.ServiceProvider.FetchIDPMetadata"

	var err error
	var ed *metadata.EntityDescriptorIDPSSO

	// Order of switch case determines IDP metadata config precedence
	switch {
	case sp.cfg.MetadataURL != "":
		ed, err = fetchIDPMetadata(sp.cfg.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return ed, nil

	case sp.cfg.MetadataXML != "":
		ed, err = parseIDPMetadata([]byte(sp.cfg.MetadataXML))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

	case sp.cfg.MetadataParameters != nil:
		ed, err = constructIDPMetadata(sp.cfg.MetadataParameters)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

	default:
		return nil, fmt.Errorf("%s: no IDP metadata configuration set: %w", op, ErrInvalidParameter)
	}

	return ed, err
}

func (sp *ServiceProvider) destination(binding core.ServiceBinding) (string, error) {
	const op = "saml.ServiceProvider.destination"

	meta, err := sp.IDPMetadata()
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

func fetchIDPMetadata(metadataURL string) (*metadata.EntityDescriptorIDPSSO, error) {
	res, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity provider metadata: %w", err)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}

	meta, err := parseIDPMetadata(raw)
	if err != nil {
		return nil, err
	}

	return meta, err
}

func parseIDPMetadata(rawXML []byte) (*metadata.EntityDescriptorIDPSSO, error) {
	var ed metadata.EntityDescriptorIDPSSO
	if err := xml.Unmarshal(rawXML, &ed); err != nil {
		return nil, fmt.Errorf("failed to parse identity provider XML metadata: %w", err)
	}

	// [SDP-MD03] https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_metadata_and_trust_management
	// IDPMetadata without a validUntil attribute on its root element MUST be rejected. IDPMetadata whose root element’s validUntil
	// attribute extends beyond a deployer- or community-imposed threshold MUST be rejected.
	// TODO: VALIDATE

	return &ed, nil
}

func constructIDPMetadata(params *MetadataParameters) (*metadata.EntityDescriptorIDPSSO, error) {
	cert, err := parsePEMCertificate([]byte(params.IDPCertificate))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyDescriptor := metadata.KeyDescriptor{
		Use: metadata.KeyTypeSigning,
		KeyInfo: metadata.KeyInfo{
			KeyInfo: dsig.KeyInfo{
				X509Data: dsig.X509Data{
					X509Certificates: []dsig.X509Certificate{
						{
							Data: base64.StdEncoding.EncodeToString(cert.Raw),
						},
					},
				},
			},
		},
	}

	idpSSODescriptor := &metadata.IDPSSODescriptor{
		SSODescriptor: metadata.SSODescriptor{
			RoleDescriptor: metadata.RoleDescriptor{
				KeyDescriptor: []metadata.KeyDescriptor{keyDescriptor},
			},
		},
		WantAuthnRequestsSigned: false,
		SingleSignOnService: []metadata.Endpoint{
			{
				Binding:  params.Binding,
				Location: params.SingleSignOnURL,
			},
		},
	}

	return &metadata.EntityDescriptorIDPSSO{
		EntityDescriptor: metadata.EntityDescriptor{
			EntityID: params.Issuer,
		},
		IDPSSODescriptor: []*metadata.IDPSSODescriptor{idpSSODescriptor},
	}, nil
}
