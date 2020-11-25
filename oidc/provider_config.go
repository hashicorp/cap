package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/go-hclog"
	sdkHttp "github.com/hashicorp/probo/sdk/http"
)

// ProviderAuthStyle determines the style of authentication used when the
// relying party makes request to the provider.
type ProviderAuthStyle int

const (
	UnknownAuthStyle ProviderAuthStyle = iota

	// AuthStyleInParams sends the "client_id" and "client_secret"
	// in the POST body as application/x-www-form-urlencoded parameters.
	AuthStyleInParams

	// AuthStyleInHeader sends the client_id and client_password
	// using HTTP Basic Authorization. This is an optional style
	// described in the OAuth2 RFC 6749 section 2.3.1.
	AuthStyleInHeader
)

type ProviderConfig struct {
	// ClientId is the relying party id
	ClientId string

	// ClientSecret is the relying party secret
	ClientSecret string

	// AuthenStyle to use when making requests to the provider's server
	AuthenStyle ProviderAuthStyle

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
	SupportedSigningAlgs []string

	// Audiences is a list optional case-sensitive strings used when verifying an id_token's "aud" claim
	Audiences []string

	// ProviderCA is an optional CA cert to use when sending requests to the provider.
	ProviderCA string

	// State is an optional store for oidc state
	State StateReadWriter

	// Logger is an optional logger
	Logger hclog.Logger
}

// NewProviderConfig composes a new config for a provider.
// Supported options:
// 	WithLogger
//  WithStateReadWriter
//	WithProviderCA
// 	WithScopes
func NewProviderConfig(issuer string, clientId, clientSecret string, rp ProviderAuthStyle, opt ...Option) (*ProviderConfig, error) {
	const op = "NewProviderConfig"
	opts := getProviderConfigOpts(opt...)
	c := &ProviderConfig{
		Issuer:       issuer,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		AuthenStyle:  rp,
		Logger:       opts.withLogger,
		Scopes:       opts.withScopes,
		ProviderCA:   opts.withProviderCA,
		State:        opts.withStateReadWriter,
	}
	if err := c.Validate(); err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrIntegrityViolation), WithMsg("invalid provider config"))
	}
	return c, nil
}

// Validate the provider configuration.  Among other validations, it verifies
// the issuer is not empty, but it doesn't verify the Issuer is discoverable via
// an http request.  SupportedSigningAlgs is validated against the list of
// currently supported algs: RS256, RS384, RS512, ES256, ES384, ES512, PS256,
// PS384, PS512
func (c *ProviderConfig) Validate() error {
	const op = "oidc.Validate"
	if c == nil {
		return NewError(ErrNilParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("provider config is nil"))
	}
	if c.ClientId == "" {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("client id is empty"))
	}
	if c.ClientSecret == "" {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("client secret is empty"))
	}
	if c.Issuer == "" {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("discovery URL is empty"))
	}

	if len(c.SupportedSigningAlgs) == 0 {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("supported algorithms is empty"))
	}
	for _, a := range c.SupportedSigningAlgs {
		switch a {
		case oidc.RS256, oidc.RS384, oidc.RS512,
			oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512:
		default:
			return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg(fmt.Sprintf("unsupported algorithm: %s", a)))
		}
	}
	return nil
}

// HttpClient is a helper function that creates a new http client for the
// provider configured
func (c *ProviderConfig) HttpClient() (*http.Client, error) {
	const op = "ProviderConfig.NewHTTPClient"
	client, err := sdkHttp.NewClient(c.ProviderCA)
	if err != nil {
		if errors.Is(err, sdkHttp.ErrInvalidCertificatePem) {
			return nil, NewError(ErrInvalidCACert, WithOp(op), WithKind(ErrIntegrityViolation), WithMsg("could not parse CA PEM value successfully"))
		}
		return nil, NewError(ErrCodeUnknown, WithOp(op), WithKind(ErrInternal), WithMsg("could not get an http client"), WithWrap(err))
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
	withScopes          []string
	withProviderCA      string
	withStateReadWriter StateReadWriter
	withLogger          hclog.Logger
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

// WithProviderCA provides an optional CA cert for the provider's config
func WithProviderCA(cert string) Option {
	return func(o interface{}) {
		if o, ok := o.(*providerConfigOptions); ok {
			o.withProviderCA = cert
		}
	}
}

// WithLogger provides an optional logger for the provider's config
func WithLogger(l hclog.Logger) Option {
	return func(o interface{}) {
		if o, ok := o.(*providerConfigOptions); ok {
			o.withLogger = l
		}
	}
}
