package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
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
	AssertionConsumerServiceURL string

	// EntityID is a globaly unique identifier of the service provider.
	EntityID string

	// Issuer is a globaly unique identifier of the identity provider.
	Issuer string

	// MetadataURL is the endpoint an IDP serves its metadata XML document.
	MetadataURL string

	// ValidUntil is a function that defines until the generate service provider metadata
	// document is valid.
	ValidUntil ValidUntilFunc

	// Certificate is used to sign SAML Authentication Requests.
	Certificate *tls.Certificate

	// IDP is an optional field that defines IDP specific configurations that are usually
	// consumed from the metadata doc. If set, the configuration will not be fetched from
	// the metadata URL.
	IDP *IDPConfig
}

func NewConfig(entityID, acs, issuer, metadata string) *Config {
	return &Config{
		EntityID:                    entityID,
		Issuer:                      issuer,
		AssertionConsumerServiceURL: acs,
		ValidUntil:                  DefaultValidUntil,
		NameIDFormat:                core.NameIDFormatEmail,
		MetadataURL:                 metadata,
		ServiceBinding:              core.ServiceBindingHTTPPost,
	}
}

func NewConfigWithCustomIDP(entityID, acs, issuer, metadata string, idp *IDPConfig) *Config {
	cfg := NewConfig(entityID, acs, issuer, metadata)
	cfg.IDP = idp

	return cfg
}

func (c *Config) Validate() error {
	const op = "saml.Config.Validate"

	if c.AssertionConsumerServiceURL == "" {
		return fmt.Errorf("%s: ACS URL is empty: %w", op, oidc.ErrInvalidParameter)
	}

	if c.EntityID == "" {
		return fmt.Errorf("%s: EntityID is empty: %w", op, oidc.ErrInvalidParameter)
	}

	if c.MetadataURL == "" && c.IDP == nil {
		return fmt.Errorf("%s: no metadata URL or IDP config set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.ServiceBinding == "" {
		return fmt.Errorf("%s: no ServiceBinding set: %w", op, oidc.ErrInvalidParameter)
	}

	if c.IDP != nil {
		if c.IDP.SSOServiceURL == "" {
			return fmt.Errorf("%s: IDP config provided but no SSO service URL not set: %w",
				op, oidc.ErrInvalidParameter)
		}
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
	return time.Now().Add(time.Hour * 24 * 7)
}
