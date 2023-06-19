package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/saml/models/core"
)

var ErrInvalidTLSCert = errors.New("invalid tls certificate")

type ValidUntilFunc func() time.Time

type IDPConfig struct {
	// SSOServiceURL is the SSO service endpoint where the authentication request
	// should be sent to. The endpoint must match the location for the given
	// service binding.
	SSOServiceURL string

	// TODO: Add more fields for the cert, crypto algorithm, etc.
	// SLOServiceURL string
}

type Config struct {
	// ServiceBinding defines the mechanism that should be used
	// when exchanging messages between the requester (SP) and responder (IDP).
	ServiceBinding core.ServiceBinding

	// NameIDFormat controls how the users at the IDP are mapped to
	// users at the SP during SSO.
	NameIDFormat core.NameIDFormat

	// AssertionConsumerServiceURL defines the endpoint at the SP where the IDP
	// will redirect to with its authentication response.
	AssertionConsumerServiceURL *url.URL

	// EntityID is a globaly unique identifier of the service provider.
	EntityID *url.URL

	// Issuer is a globaly unique identifier of the identity provider.
	Issuer *url.URL

	// MetadataURL is the endpoint an IDP serves its metadata XML document.
	MetadataURL *url.URL

	// ValidUntil is a function that defines until the generate service provider metadata
	// document is valid.
	ValidUntil ValidUntilFunc

	// Certificate is used to sign SAML Authentication Requests.
	Certificate *tls.Certificate
}

func NewConfig(entityID, acs, issuer, metadata *url.URL) *Config {
	return &Config{
		EntityID:                    entityID,
		Issuer:                      issuer,
		AssertionConsumerServiceURL: acs,
		ValidUntil:                  DefaultValidUntil,
		NameIDFormat:                core.NameIDFormatEmail,
		MetadataURL:                 metadata,
	}
}

func (c *Config) Validate() error {
	const op = "saml.Config.Validate"

	if c.AssertionConsumerServiceURL == nil {
		return fmt.Errorf("%s: ACS URL is empty: %w", op, oidc.ErrInvalidParameter)
	}

	if c.EntityID == nil {
		return fmt.Errorf("%s: EntityID is empty: %w", op, oidc.ErrInvalidParameter)
	}

	if c.MetadataURL == nil {
		return fmt.Errorf("%s: no metadata URL or IDP config set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.Certificate != nil {
		err := c.ValidateTLSCertificate()
		return fmt.Errorf("%s: failed to validate tls certificate: %w", op, err)
	}

	return nil
}

func (c *Config) ValidateTLSCertificate() error {
	const op = "saml.Config.ValidateTLSCertificate"

	_, ok := c.Certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("%s: no RSA key: %w", op, ErrInvalidTLSCert)
	}

	if len(c.Certificate.Certificate) == 0 {
		return fmt.Errorf("%s: no certificate provided: %w", op, ErrInvalidTLSCert)
	}

	return nil
}

func DefaultValidUntil() time.Time {
	return time.Now().Add(time.Hour * 24 * 365)
}
