package saml

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/cap/oidc"
)

var ErrInvalidTLSCert = errors.New("invalid tls certificate")

type ValidUntilFunc func() time.Time

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
	// document is valid. (optional)
	ValidUntil ValidUntilFunc
}

func NewConfig(entityID, acs, issuer, metadata *url.URL) (*Config, error) {
	const op = "saml.NewConfig"

	cfg := &Config{
		EntityID:                    entityID,
		Issuer:                      issuer,
		AssertionConsumerServiceURL: acs,
		ValidUntil:                  DefaultValidUntil,
		MetadataURL:                 metadata,
	}

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("%s: invalid provider config: %w", op, err)
	}

	return cfg, nil
}

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

	return nil
}

func DefaultValidUntil() time.Time {
	return time.Now().Add(time.Hour * 24 * 365)
}
