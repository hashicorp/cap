package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/cap/oidc/internal/strutils"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

// Provider provides integration with an OIDC provider.
//  It's primary capabilities include:
//   * Kicking off a user authentication with p.AuthURL(...)
//
//   * The authorization code flow by exchanging an auth code for tokens in
//     p.Exchange(...)
//
//   * Verifying an id_token issued by a provider with p.VerifyIdToken(...)
//
//   * Retrieving a user's OAuth claims with p.UserInfo(...)
type Provider struct {
	config   *Config
	provider *oidc.Provider

	// client uses a pooled transport that uses the provider's config CA
	// certificate PEM if provided, otherwise it will use the installed system
	// CA chain.  This client's resources idle connections are closed in
	// Provider.Done()
	client *http.Client

	mu sync.Mutex

	// backgroundCtx is the context used by the provider for background
	// activities like: refreshing JWKs ket sets, refreshing tokens, etc
	backgroundCtx context.Context

	// backgroundCtxCancel is used to cancel any background activities running
	// in spawned go routines.
	backgroundCtxCancel context.CancelFunc
}

// NewProvider creates and initializes a Provider for the OIDC
// authorization code flow.  Intializing the the provider, includes making an
// http request to the provider's issuer.
//
// See Provider.Stop() which must be called to release provider resources.
func NewProvider(c *Config) (*Provider, error) {
	const op = "NewProvider"
	if c == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: provider config is invalid: %w", op, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// initializing the Provider with it's background ctx/cancel will
	// allow us to use p.Stop() to release any resources when returning errors
	// from this function.
	p := &Provider{
		config:              c,
		backgroundCtx:       ctx,
		backgroundCtxCancel: cancel,
	}

	oidcCtx, err := p.HttpClientContext(p.backgroundCtx)
	if err != nil {
		p.Done() // release the backgroundCtxCancel resources
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}

	provider, err := oidc.NewProvider(oidcCtx, c.Issuer) // makes http req to issuer for discovery
	if err != nil {
		p.Done() // release the backgroundCtxCancel resources
		// we don't know what's causing the problem, so we won't classify the
		// error with a Kind
		return nil, fmt.Errorf("%s: unable to create provider: %w", op, err)
	}
	p.provider = provider

	return p, nil
}

// Done with the provider's background resources and must be called for every
// Provider created
func (p *Provider) Done() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.backgroundCtxCancel != nil {
		p.backgroundCtxCancel()
		p.backgroundCtxCancel = nil
	}

	// release the http.Client's pooled transport resources.
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
}

// AuthURL will generate a URL the caller can use to kick off an OIDC
// authorization code (or an implicit flow) with an IdP.  The redirectURL is the
// URL the IdP should use as a redirect after the authentication/authorization
// is completed by the user.  Providing a WithImplicitFlow() option overrides
// the default authorization code default flow.
//
//  See NewState() to create an oidc flow State with a valid Id and Nonce that
// will uniquely identify the user's authentication attempt throughout the flow.
func (p *Provider) AuthURL(ctx context.Context, s State, opt ...Option) (url string, e error) {
	const op = "Provider.AuthURL"
	opts := getProviderOpts(opt...)
	if s.ID() == "" {
		return "", fmt.Errorf("%s: state id is empty: %w", op, ErrInvalidParameter)
	}
	if s.Nonce() == "" {
		return "", fmt.Errorf("%s: state nonce is empty: %w", op, ErrInvalidParameter)
	}
	if s.ID() == s.Nonce() {
		return "", fmt.Errorf("%s: state id and nonce cannot be equal: %w", op, ErrInvalidParameter)
	}

	// Add the "openid" scope, which is a required scope for oidc flows
	scopes := p.config.Scopes
	if !strutils.StrListContains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, p.config.Scopes...)
	}

	// Configure an OpenID Connect aware OAuth2 client
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  p.config.RedirectURL,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}
	authCodeOpts := []oauth2.AuthCodeOption{
		oidc.Nonce(s.Nonce()),
	}
	if opts.withImplicitFlow != nil {
		reqTokens := []string{"id_token"}
		if !opts.withImplicitFlow.withoutAccessToken {
			reqTokens = append(reqTokens, "token")
		}
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("response_mode", "form_post"), oauth2.SetAuthURLParam("response_type", strings.Join(reqTokens, " ")))
	}
	return oauth2Config.AuthCodeURL(s.ID(), authCodeOpts...), nil
}

// Exchange will request a token from the oidc token endpoint, using the
// authorizationCode and authorizationState it received in an earlier successful
// oidc authentication response.
//
// It will also validate the authorizationState it receives against the
// existing State for the user's oidc authentication flow.
//
// On success, the Token returned will include an IDToken and may include an
// AccessToken and RefreshToken.
func (p *Provider) Exchange(ctx context.Context, s State, authorizationState string, authorizationCode string) (*Tk, error) {
	const op = "Provider.Exchange"
	if p.config == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if s.ID() != authorizationState {
		return nil, fmt.Errorf("%s: authentication state and authorization state are not equal: %w", op, ErrInvalidParameter)
	}
	if s.IsExpired() {
		return nil, fmt.Errorf("%s: authentication state is expired: %w", op, ErrInvalidParameter)
	}

	oidcCtx, err := p.HttpClientContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}

	// Add the "openid" scope, which is a required scope for oidc flows
	// * TODO (jimlambrt 11/2020): make sure these additional scopes work as intended.
	scopes := append([]string{oidc.ScopeOpenID}, p.config.Scopes...)

	var oauth2Config = oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  p.config.RedirectURL,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}

	oauth2Token, err := oauth2Config.Exchange(oidcCtx, authorizationCode)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to exchange auth code with provider: %w", op, err)
	}

	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%s: id_token is missing from auth code exchange: %w", op, ErrMissingIdToken)
	}
	t, err := NewToken(IDToken(idToken), oauth2Token, WithNow(p.config.NowFunc))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create new id_token: %w", op, err)
	}
	if err := p.VerifyIDToken(ctx, t.IDToken(), s.Nonce()); err != nil {
		return nil, fmt.Errorf("%s: id_token failed verification: %w", op, err)
	}
	if t.AccessToken() != "" {
		if err := t.IDToken().VerifyAccessToken(t.AccessToken()); err != nil {
			return nil, fmt.Errorf("%s: access_token failed verification: %w", op, err)
		}
	}
	return t, nil
}

// UserInfo gets the UserInfo claims from the provider using the token produced
// by the tokenSource.
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource, claims interface{}) error {
	// TODO: make sure we follow the spec for validating the response.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponseValidation
	const op = "Provider.UserInfo"
	if tokenSource == nil {
		return fmt.Errorf("%s: token source is nil: %w", op, ErrNilParameter)
	}
	if claims == nil {
		return fmt.Errorf("%s: claims interface is nil: %w", op, ErrNilParameter)
	}
	if reflect.ValueOf(claims).Kind() != reflect.Ptr {
		return fmt.Errorf("%s: interface parameter must to be a pointer: %w", op, ErrInvalidParameter)
	}
	oidcCtx, err := p.HttpClientContext(ctx)
	if err != nil {
		return fmt.Errorf("%s: unable to create http client: %w", op, err)
	}

	userinfo, err := p.provider.UserInfo(oidcCtx, tokenSource)
	if err != nil {
		return fmt.Errorf("%s: provider UserInfo request failed: %w", op, err)
	}
	err = userinfo.Claims(&claims)
	if err != nil {
		return fmt.Errorf("%s: failed to get UserInfo claims: %w", op, err)
	}
	return nil
}

// VerifyIDToken will verify the inbound IdToken.
//  It verifies:
//   * signature (including if a supported signing algorithm was used)
//   * issuer (iss)
//   * expiration (exp)
//   * issued at (iat) (with a leeway of 1 min)
//   * not before (nbf) (with a leeway of 1 min)
//   * nonce (nonce)
//   * audience (aud) contains all audiences required from the provider's config
//   * when there are multiple audiences (aud), then one of them must equal
//     the client_id
//   * when present, the authorized party (azp) must equal the client id
//   * when there are multiple audiences (aud), then the authorized party (azp)
//     must equal the client id
//   * when there is a single audience (aud) and it is not equal to the client
//     id, then the authorized party (azp) must equal the client id
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Provider) VerifyIDToken(ctx context.Context, t IDToken, nonce string) error {
	const op = "Provider.VerifyIdToken"
	if t == "" {
		return fmt.Errorf("%s: id_token is empty: %w", op, ErrInvalidParameter)
	}
	if nonce == "" {
		return fmt.Errorf("%s: nonce is empty: %w", op, ErrInvalidParameter)
	}
	algs := []string{}
	for _, a := range p.config.SupportedSigningAlgs {
		algs = append(algs, string(a))
	}
	oidcConfig := &oidc.Config{
		SupportedSigningAlgs: algs,
		ClientID:             p.config.ClientID,
		Now:                  p.config.Now,
	}
	verifier := p.provider.Verifier(oidcConfig)
	nowTime := p.config.Now() // intialized right after the Verifier so there idea of nowTime sort of coresponds.
	leeway := 1 * time.Minute

	// verifier.Verify will check the supported algs, signature, iss, exp, nbf, the aud includes the client_id
	oidcIDToken, err := verifier.Verify(ctx, string(t))
	if err != nil {
		return fmt.Errorf("%s: invalid id_token signature: %w", op, err)
	}
	// so.. we still need to check: nonce, iat, auth_time, azp, the aud includes
	// additional audiences configured.
	if oidcIDToken.Nonce != nonce {
		return fmt.Errorf("%s: invalid id_token nonce: %w", op, ErrInvalidNonce)
	}
	if nowTime.Add(leeway).Before(oidcIDToken.IssuedAt) {
		return fmt.Errorf("%s: invalid id_token current time %v before the iat (issued at) time %v: %w", op, nowTime, oidcIDToken.IssuedAt, ErrInvalidIssuedAt)
	}

	if err := func() error {
		if len(p.config.Audiences) > 0 {
			for _, v := range p.config.Audiences {
				if strutils.StrListContains(oidcIDToken.Audience, v) {
					return nil
				}
			}
			return ErrInvalidAudience
		}
		return nil
	}(); err != nil {
		return fmt.Errorf("%s: invalid id_token audiences: %w", op, err)
	}
	if len(oidcIDToken.Audience) > 1 && strutils.StrListContains(oidcIDToken.Audience, p.config.ClientID) {
		return fmt.Errorf("%s: invalid id_token: multiple audiences (%s) and one of them is not equal client_id (%s): %w", op, oidcIDToken.Audience, p.config.ClientID, ErrInvalidAudience)
	}

	var claims map[string]interface{}
	if err := t.Claims(&claims); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	azp, foundAzp := claims["azp"]
	if foundAzp {
		if azp != p.config.ClientID {
			return fmt.Errorf("%s: invalid id_token: authorized party (%s) is not equal client_id (%s): %w", op, azp, p.config.ClientID, ErrInvalidAuthorizedParty)
		}
	}
	if len(oidcIDToken.Audience) > 1 && azp != p.config.ClientID {
		return fmt.Errorf("%s: invalid id_token: multiple audiences and authorized party (%s) is not equal client_id (%s): %w", op, azp, p.config.ClientID, ErrInvalidAuthorizedParty)
	}
	if (len(oidcIDToken.Audience) == 1 && oidcIDToken.Audience[0] != p.config.ClientID) && azp != p.config.ClientID {
		return fmt.Errorf(
			"%s: invalid id_token: one audience (%s) which is not the client_id (%s) and authorized party (%s) is not equal client_id (%s): %w",
			op,
			oidcIDToken.Audience[0],
			p.config.ClientID,
			azp,
			p.config.ClientID,
			ErrInvalidAuthorizedParty)
	}

	return nil
}

// HttpClient returns an http.Client for the provider. The returned client uses
// a pooled transport (so it can reuse connections) that uses the provider's
// config CA certificate PEM if provided, otherwise it will use the installed
// system CA chain.  This client's idle connections are closed in
// Provider.Done()
func (p *Provider) HttpClient() (*http.Client, error) {
	const op = "Provider.NewHTTPClient"
	if p.client != nil {
		return p.client, nil
	}
	// since it's called by the provider factory, we need to check that the
	// config isn't nil
	if p.config == nil {
		return nil, fmt.Errorf("%s: the provider's config is nil %w", op, ErrNilParameter)
	}

	tr := cleanhttp.DefaultPooledTransport()

	if p.config.ProviderCA != "" {
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(p.config.ProviderCA)); !ok {
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidCACert)
		}

		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	c := &http.Client{
		Transport: tr,
	}
	p.client = c
	return p.client, nil
}

// HttpClientContext returns a new Context that carries the provider's HTTP
// client. This method sets the same context key used by the
// github.com/coreos/go-oidc and golang.org/x/oauth2 packages, so the returned
// context works for those packages as well.
func (p *Provider) HttpClientContext(ctx context.Context) (context.Context, error) {
	const op = "Provider.HttpClientContext"
	c, err := p.HttpClient()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)

	}
	// simple to implement as a wrapper for the coreos package
	return oidc.ClientContext(ctx, c), nil
}

type implicitFlow struct {
	withoutAccessToken bool
}

// providerOptions is the set of available options
type providerOptions struct {
	withImplicitFlow *implicitFlow
}

// getProviderDefaults is a handy way to get the defaults at runtime and
// during unit tests.
func providerDefaults() providerOptions {
	return providerOptions{}
}

// getProviderOpts gets the defaults and applies the opt overrides passed
// in.
func getProviderOpts(opt ...Option) providerOptions {
	opts := providerDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithImplicitFlow provides an option to use an implicit flow for the auth URL
// being requested. Getting an id_token and access_token is the default, and
// optionally passing a true bool that will prevent an access_token from being
// requested during the flow
func WithImplicitFlow(args ...interface{}) Option {
	withoutAccessToken := false
	for _, arg := range args {
		switch arg := arg.(type) {
		case bool:
			if arg {
				withoutAccessToken = true
			}
		}
	}
	return func(o interface{}) {
		if o, ok := o.(*providerOptions); ok {
			o.withImplicitFlow = &implicitFlow{
				withoutAccessToken: withoutAccessToken,
			}
		}
	}
}
