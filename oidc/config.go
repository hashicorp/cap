package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc"
	sdkHttp "github.com/hashicorp/cap/sdk/http"
	strutil "github.com/hashicorp/cap/sdk/strutils"
)

type ClientSecret string

// RedactedClientSecret is the redacted string or json for an oauth client secret
const RedactedClientSecret = "[REDACTED: client secret]"

// String will redact the client secret
func (t ClientSecret) String() string {
	return RedactedClientSecret
}

// MarshalJSON will redact the client secret
func (t ClientSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedClientSecret)
}

// Config represents the configuration for a typical 3-legged OIDC
// authorization code flow.
type Config struct {
	// ClientId is the relying party id
	ClientId string

	// ClientSecret is the relying party secret
	ClientSecret ClientSecret

	// Scopes is a list of additional oidc scopes to request of the provider
	// The required "oidc" scope is requested by default, and should be part of
	// this optional list.
	Scopes []string

	// Issuer is a case-sensitive URL string using the https scheme that
	// contains scheme, host, and optionally, port number and path components
	// and no query or fragment components.
	Issuer string

	// SupportedSigningAlgs is a list of supported signing algorithms. List of
	// currently supported algs: RS256, RS384, RS512, ES256, ES384, ES512,
	// PS256, PS384, PS512
	SupportedSigningAlgs []Alg

	RedirectUrl string

	// Audiences is a list optional case-sensitive strings used when verifying an id_token's "aud" claim
	Audiences []string

	// ProviderCA is an optional CA cert to use when sending requests to the provider.
	ProviderCA string
}

// NewConfig composes a new config for a provider.
// Supported options:
//  WithStateReadWriter
//	WithProviderCA
// 	WithScopes
func NewConfig(issuer string, clientId string, clientSecret ClientSecret, supported []Alg, redirectUrl string, opt ...Option) (*Config, error) {
	const op = "NewProviderConfig"
	opts := getProviderConfigOpts(opt...)
	c := &Config{
		Issuer:               issuer,
		ClientId:             clientId,
		ClientSecret:         clientSecret,
		SupportedSigningAlgs: supported,
		RedirectUrl:          redirectUrl,
		Scopes:               opts.withScopes,
		ProviderCA:           opts.withProviderCA,
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid provider config: %w", err)
	}
	return c, nil
}

// Validate the provider configuration.  Among other validations, it verifies
// the issuer is not empty, but it doesn't verify the Issuer is discoverable via
// an http request.  SupportedSigningAlgs is validated against the list of
// currently supported algs: RS256, RS384, RS512, ES256, ES384, ES512, PS256,
// PS384, PS512
func (c *Config) Validate() error {
	const op = "oidc.Validate"
	if c == nil {
		return fmt.Errorf("provider config is nil: %w", ErrNilParameter)
	}
	if c.ClientId == "" {
		return fmt.Errorf("client id is empty: %w", ErrInvalidParameter)
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client secret is empty: %w", ErrInvalidParameter)
	}
	if c.Issuer == "" {
		return fmt.Errorf("discovery URL is empty: %w", ErrInvalidParameter)
	}
	if c.RedirectUrl == "" {
		return fmt.Errorf("redirect URL is empty: %w", ErrInvalidParameter)
	}
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("issuer %s is invalid: %w", c.Issuer, err)
	}
	if !strutil.StrListContains([]string{"https", "http"}, u.Scheme) {
		return fmt.Errorf("issuer %s schema is not http or https: %w", c.Issuer, err)
	}
	if len(c.SupportedSigningAlgs) == 0 {
		return fmt.Errorf("supported algorithms is empty: %w", ErrInvalidParameter)
	}
	for _, a := range c.SupportedSigningAlgs {
		if _, ok := supportedAlgorithms[a]; !ok {
			return fmt.Errorf("unsupported algorithm %s: %w", a, ErrInvalidParameter)
		}
	}
	return nil
}

// HttpClient is a helper function that creates a new http client for the
// provider configured
func (c *Config) HttpClient() (*http.Client, error) {
	const op = "ProviderConfig.NewHTTPClient"
	client, err := sdkHttp.NewClient(c.ProviderCA)
	if err != nil {
		if errors.Is(err, sdkHttp.ErrInvalidCertificatePem) {
			return nil, fmt.Errorf("could not parse CA PEM value: %w", ErrInvalidCACert)
		}
		return nil, fmt.Errorf("could not get an http client: %w", err)
	}
	return client, nil
}

// HttpClientContext is a helper function that returns a new Context that
// carries the provided HTTP client. This method sets the same context key used
// by the github.com/coreos/go-oidc and golang.org/x/oauth2 packages, so the
// returned context works for those packages as well.
func HttpClientContext(ctx context.Context, client *http.Client) context.Context {
	// simple to implement as a wrapper for the coreos package
	return oidc.ClientContext(ctx, client)
}

// providerConfigOptions is the set of available options
type providerConfigOptions struct {
	withScopes     []string
	withAudiences  []string
	withProviderCA string
}

// getProviderConfigDefaults is a handy way to get the defaults at runtime and
// during unit tests.
func providerConfigDefaults() providerConfigOptions {
	return providerConfigOptions{}
}

// getProviderConfigOpts gets the defaults and applies the opt overrides passed
// in.
func getProviderConfigOpts(opt ...Option) providerConfigOptions {
	opts := providerConfigDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithScopes provides an optional list of scopes for the provider's config
func WithScopes(scopes []string) Option {
	return func(o interface{}) {
		if o, ok := o.(*providerConfigOptions); ok {
			o.withScopes = scopes
		}
	}
}

// WithAudiences provides an optional list of audiences for the provider's config
func WithAudiences(auds []string) Option {
	return func(o interface{}) {
		if o, ok := o.(*providerConfigOptions); ok {
			o.withAudiences = auds
		}
	}
}

// WithProviderCA provides an optional CA cert for the provider's config
func WithProviderCA(cert string) Option {
	return func(o interface{}) {
		if o, ok := o.(*providerConfigOptions); ok {
			o.withProviderCA = cert
		}
	}
}
