package saml

import (
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/go-uuid"
)

type ValidUntilFunc func() time.Time

type GenerateAuthRequestIDFunc func() (string, error)

type Config struct {
	// AssertionConsumerServiceURL defines the endpoint at the service provider where
	// the identity provider will redirect to with its authentication response. Must be
	// a valid URL. Required.
	AssertionConsumerServiceURL string

	// EntityID is a globally unique identifier of the service provider. Must be a
	// valid URL. Required.
	EntityID string

	// MetadataURL is the endpoint an identity provider serves its metadata XML document.
	// Must be a valid URL. Takes precedence over MetadataXML and MetadataParameters.
	// Required if MetadataXML or MetadataParameters not set.
	MetadataURL string

	// MetadataXML is the XML-formatted metadata an identity provider provides to
	// configure a service provider. Takes precedence over MetadataParameters. Optional.
	MetadataXML string

	// MetadataParameters are the individual parameters an identity provider provides
	// to configure a service provider. Optional.
	MetadataParameters *MetadataParameters

	// ValidUntil is a function that defines the time after which the service provider
	// metadata document is considered invalid. Optional.
	ValidUntil ValidUntilFunc

	// GenerateAuthRequestID generates an XSD:ID conforming ID.
	GenerateAuthRequestID GenerateAuthRequestIDFunc
}

type MetadataParameters struct {
	// Issuer is a globally unique identifier of the identity provider.
	// Must be a valid URL. Required.
	Issuer string

	// SingleSignOnURL is the single sign-on service URL of the identity provider.
	// Must be a valid URL. Required.
	SingleSignOnURL string

	// IDPCertificate is the PEM-encoded public key certificate provided by the identity
	// provider. Used to verify response and assertion signatures. Required.
	IDPCertificate string

	// Binding defines the binding that will be used for authentication requests. Defaults
	// to HTTP-POST binding. Optional.
	Binding core.ServiceBinding
}

func (c *MetadataParameters) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer not set")
	}
	if _, err := url.Parse(c.Issuer); err != nil {
		return fmt.Errorf("provided Issuer is not a valid URL: %w", err)
	}

	if c.SingleSignOnURL == "" {
		return fmt.Errorf("SSO URL not set")
	}
	if _, err := url.Parse(c.SingleSignOnURL); err != nil {
		return fmt.Errorf("provided SSO URL is not a valid URL: %w", err)
	}

	if _, err := parsePEMCertificate([]byte(c.IDPCertificate)); err != nil {
		return fmt.Errorf("failed to parse IDP certificate: %w", err)
	}

	return nil
}

// WithMetadataXML provides optional identity provider metadata in the form of an XML
// document that can be used to configure the service provider.
func WithMetadataXML(metadata string) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withMetadataXML = metadata
		}
	}
}

// WithMetadataParameters provides optional static metadata from an identity provider
// that can be used to configure the service provider.
func WithMetadataParameters(metadata MetadataParameters) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			if metadata.Binding == "" {
				metadata.Binding = core.ServiceBindingHTTPPost
			}
			o.withMetadataParameters = &metadata
		}
	}
}

// WithValidUntil provides the time after which the service provider metadata
// document is considered invalid
func WithValidUntil(validUntil ValidUntilFunc) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withValidUntil = validUntil
		}
	}
}

// WithGenerateAuthRequestID provides an XSD:ID conforming ID for authentication requests
func WithGenerateAuthRequestID(generateAuthRequestID GenerateAuthRequestIDFunc) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withGenerateAuthRequestID = generateAuthRequestID
		}
	}
}

// NewConfig creates a new configuration for a service provider. Identity provider
// metadata can be provided via the metadataURL parameter or the WithMetadataXML
// and WithMetadataParameters options. The metadataURL will always take precedence
// if options are provided.
//
// Options:
// - WithValidUntil
// - WithMetadataXML
// - WithMetadataParameters
func NewConfig(entityID, acs, metadataURL string, opt ...Option) (*Config, error) {
	const op = "saml.NewConfig"

	opts := getConfigOptions(opt...)

	cfg := &Config{
		EntityID:                    entityID,
		AssertionConsumerServiceURL: acs,
		MetadataURL:                 metadataURL,
		MetadataXML:                 opts.withMetadataXML,
		MetadataParameters:          opts.withMetadataParameters,
		ValidUntil:                  opts.withValidUntil,
		GenerateAuthRequestID:       opts.withGenerateAuthRequestID,
	}

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("%s: invalid provider config: %w", op, err)
	}

	return cfg, nil
}

// Validate validates the provided configuration.
func (c *Config) Validate() error {
	const op = "saml.Config.Validate"

	if c.AssertionConsumerServiceURL == "" {
		return fmt.Errorf("%s: ACS URL not set: %w", op, ErrInvalidParameter)
	}
	if _, err := url.Parse(c.AssertionConsumerServiceURL); err != nil {
		return fmt.Errorf("%s: provided ACS URL is not a valid URL: %w", op, ErrInvalidParameter)
	}

	if c.EntityID == "" {
		return fmt.Errorf("%s: EntityID not set: %w", op, ErrInvalidParameter)
	}
	if _, err := url.Parse(c.EntityID); err != nil {
		return fmt.Errorf("%s: provided Entity ID is not a valid URL: %w", op, ErrInvalidParameter)
	}

	if c.MetadataURL == "" && c.MetadataXML == "" && c.MetadataParameters == nil {
		return fmt.Errorf("%s: One of MetadataURL, MetadataXML, or MetadataParameters "+
			"must be set: %w", op, ErrInvalidParameter)
	}
	if c.MetadataURL != "" {
		if _, err := url.Parse(c.MetadataURL); err != nil {
			return fmt.Errorf("%s: provided Metadata URL is not a valid URL: %w", op, ErrInvalidParameter)
		}
	}
	if c.MetadataXML != "" {
		if _, err := parseIDPMetadata([]byte(c.MetadataXML)); err != nil {
			return fmt.Errorf("%s: %s: %w", op, err.Error(), ErrInvalidParameter)
		}
	}

	if c.MetadataParameters != nil {
		if err := c.MetadataParameters.Validate(); err != nil {
			return fmt.Errorf("%s: %s: %w", op, err.Error(), ErrInvalidParameter)
		}
	}

	if c.GenerateAuthRequestID == nil {
		return fmt.Errorf(
			"%s: GenerateAuthRequestID func not provided: %w",
			op,
			ErrInvalidParameter,
		)
	}

	return nil
}

type configOptions struct {
	withMetadataXML           string
	withMetadataParameters    *MetadataParameters
	withValidUntil            ValidUntilFunc
	withGenerateAuthRequestID GenerateAuthRequestIDFunc
}

func configOptionsDefault() configOptions {
	return configOptions{
		withValidUntil: DefaultValidUntil,
	}
}

func getConfigOptions(opt ...Option) configOptions {
	opts := configOptionsDefault()
	ApplyOpts(&opts, opt...)

	// Apply defaults to options
	if opts.withGenerateAuthRequestID == nil {
		opts.withGenerateAuthRequestID = DefaultGenerateAuthRequestID
	}
	if opts.withValidUntil == nil {
		opts.withValidUntil = DefaultValidUntil
	}

	return opts
}

// DefaultGenerateAuthRequestID generates an auth XSD:ID conform ID.
// A UUID prefixed with an underscore.
func DefaultGenerateAuthRequestID() (string, error) {
	newID, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}

	// Request IDs have to be xsd:ID, which means they need to start with an underscore or letter,
	// which is not always given for UUIDs.
	return fmt.Sprintf("_%s", newID), nil
}

func DefaultValidUntil() time.Time {
	return time.Now().Add(time.Hour * 24 * 365)
}
