package saml

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-uuid"
)

var ErrInvalidTLSCert = errors.New("invalid tls certificate")

type ValidUntilFunc func() time.Time

type GenerateAuthRequestIDFunc func() (string, error)

type Config struct {
	// AssertionConsumerServiceURL defines the endpoint at the SP where the IDP
	// will redirect to with its authentication response. (required)
	AssertionConsumerServiceURL *url.URL

	// EntityID is a globaly unique identifier of the service provider. (required)
	EntityID *url.URL

	// Issuer is a globaly unique identifier of the identity provider. (required)
	Issuer *url.URL

	// MetadataURL is the endpoint an IDP serves its metadata XML document. (required)
	MetadataURL *url.URL

	// ValidUntil is a function that defines until the generated service provider metadata
	// document is valid.
	ValidUntil ValidUntilFunc

	// GenerateAuthRequestID generates a XSD:ID conform ID.
	GenerateAuthRequestID GenerateAuthRequestIDFunc
}

// NewConfig creates a new SAML Config.
func NewConfig(entityID, acs, issuer, metadata *url.URL) (*Config, error) {
	const op = "saml.NewConfig"

	cfg := &Config{
		EntityID:                    entityID,
		Issuer:                      issuer,
		AssertionConsumerServiceURL: acs,
		MetadataURL:                 metadata,

		ValidUntil:            DefaultValidUntil,
		GenerateAuthRequestID: GenerateAuthRequestID,
	}

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("%s: invalid provider config: %w", op, err)
	}

	return cfg, nil
}

// GenerateAuthRequestID generates an auth XSD:ID conform ID.
// A UUID prefixed with an underscore.
func GenerateAuthRequestID() (string, error) {
	newID, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}

	// Request IDs have to be xsd:ID, which means they need to start with an underscore or letter,
	// which is not always given for UUIDs.
	return fmt.Sprintf("_%s", newID), nil
}

// Validate validates the provided configuration.
func (c *Config) Validate() error {
	const op = "saml.Config.Validate"

	if c.AssertionConsumerServiceURL == nil {
		return fmt.Errorf("%s: ACS URL not set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.EntityID == nil {
		return fmt.Errorf("%s: EntityID not set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.Issuer == nil {
		return fmt.Errorf("%s: Issuer not set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.MetadataURL == nil {
		return fmt.Errorf("%s: Metadata URL not set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.ValidUntil == nil {
		return fmt.Errorf("%s: ValidUntil func not provided: %w", op, oidc.ErrInvalidParameter)
	}

	if c.GenerateAuthRequestID == nil {
		return fmt.Errorf(
			"%s: GenerateAuthRequestID func not provided: %w",
			op,
			oidc.ErrInvalidParameter,
		)
	}

	return nil
}

// DefaultValidUntil
func DefaultValidUntil() time.Time {
	return time.Now().Add(time.Hour * 24 * 365)
}
