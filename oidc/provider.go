package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
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
//   * Kicking off a user authentication via either the authorization code flow
//     (with optional PKCE) or implicit flow via the URL from p.AuthURL(...)
//
//   * The authorization code flow (with optional PKCE) by exchanging an auth
//     code for tokens in p.Exchange(...)
//
//   * Verifying an id_token issued by a provider with p.VerifyIDToken(...)
//
//   * Retrieving a user's OAuth claims with p.UserInfo(...)
type Provider struct {
	config   *Config
	provider *oidc.Provider

	// client uses a pooled transport that uses the config's ProviderCA if
	// provided, otherwise it will use the installed system CA chain.  This
	// client's resources idle connections are closed in Provider.Done()
	client *http.Client

	mu sync.Mutex

	// backgroundCtx is the context used by the provider for background
	// activities like: refreshing JWKs Key sets, refreshing tokens, etc
	backgroundCtx context.Context

	// backgroundCtxCancel is used to cancel any background activities running
	// in spawned go routines.
	backgroundCtxCancel context.CancelFunc
}

// NewProvider creates and initializes a Provider. Intializing the provider,
// includes making an http request to the provider's issuer.
//
// See Provider.Done() which must be called to release provider resources.
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

	oidcCtx, err := p.HTTPClientContext(p.backgroundCtx)
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
	// checking for nil here prevents a panic when developers neglect to check
	// the for an error before deferring a call to p.Done():
	// 		p, err := NewProvider(...)
	// 		defer p.Done()
	// 		if err != nil { ... }
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
// authorization code (with optional PKCE) or an implicit flow with an IdP.
//
// See NewState() to create an oidc flow State with a valid ID and Nonce that
// will uniquely identify the user's authentication attempt throughout the flow.
func (p *Provider) AuthURL(ctx context.Context, s State) (url string, e error) {
	const op = "Provider.AuthURL"
	if s.ID() == "" {
		return "", fmt.Errorf("%s: state id is empty: %w", op, ErrInvalidParameter)
	}
	if s.Nonce() == "" {
		return "", fmt.Errorf("%s: state nonce is empty: %w", op, ErrInvalidParameter)
	}
	if s.ID() == s.Nonce() {
		return "", fmt.Errorf("%s: state id and nonce cannot be equal: %w", op, ErrInvalidParameter)
	}
	withImplicit, withImplicitAccessToken := s.ImplicitFlow()
	if s.PKCEVerifier() != nil && withImplicit {
		return "", fmt.Errorf("%s: state requests both implicit flow and authorization code with PKCE: %w", op, ErrInvalidParameter)
	}
	if s.RedirectURL() == "" {
		return "", fmt.Errorf("%s: state redirect URL is empty: %w", op, ErrInvalidParameter)
	}
	if err := p.validRedirect(s.RedirectURL()); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	var scopes []string
	switch {
	case len(s.Scopes()) > 0:
		scopes = s.Scopes()
	default:
		scopes = p.config.Scopes
	}
	// Add the "openid" scope, which is a required scope for oidc flows
	if !strutils.StrListContains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	// Configure an OpenID Connect aware OAuth2 client
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  s.RedirectURL(),
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}
	authCodeOpts := []oauth2.AuthCodeOption{
		oidc.Nonce(s.Nonce()),
	}
	if withImplicit {
		reqTokens := []string{"id_token"}
		if withImplicitAccessToken {
			reqTokens = append(reqTokens, "token")
		}
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("response_mode", "form_post"), oauth2.SetAuthURLParam("response_type", strings.Join(reqTokens, " ")))
	}
	if s.PKCEVerifier() != nil {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("code_challenge", s.PKCEVerifier().Challenge()), oauth2.SetAuthURLParam("code_challenge_method", string(s.PKCEVerifier().Method())))
	}
	if secs, exp := s.MaxAge(); !exp.IsZero() {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(secs))))
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
// On success, the Token returned will include an IDToken and may
// include an AccessToken and RefreshToken.
//
// See Provider.VerifyIDToken for info about id_token verification.
//
// The id_token at_hash claim is verified when present. (see
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation)
//
// The id_token c_hash claim is verified when present.
func (p *Provider) Exchange(ctx context.Context, s State, authorizationState string, authorizationCode string) (*Tk, error) {
	const op = "Provider.Exchange"
	if p.config == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if s == nil {
		return nil, fmt.Errorf("%s: state is nil: %w", op, ErrNilParameter)

	}
	if withImplicit, _ := s.ImplicitFlow(); withImplicit {
		return nil, fmt.Errorf("%s: state (%s) should not be using the implicit flow: %w", op, s.ID(), ErrInvalidFlow)
	}
	if s.ID() != authorizationState {
		return nil, fmt.Errorf("%s: authentication state and authorization state are not equal: %w", op, ErrInvalidParameter)
	}
	if s.RedirectURL() == "" {
		return nil, fmt.Errorf("%s: authentication state redirect URL is empty: %w", op, ErrInvalidParameter)
	}
	if err := p.validRedirect(s.RedirectURL()); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if s.IsExpired() {
		return nil, fmt.Errorf("%s: authentication state is expired: %w", op, ErrInvalidParameter)
	}

	oidcCtx, err := p.HTTPClientContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}
	var scopes []string
	switch {
	case len(s.Scopes()) > 0:
		scopes = s.Scopes()
	default:
		scopes = p.config.Scopes
	}
	// Add the "openid" scope, which is a required scope for oidc flows
	scopes = append([]string{oidc.ScopeOpenID}, scopes...)

	var oauth2Config = oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  s.RedirectURL(),
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}
	var authCodeOpts []oauth2.AuthCodeOption
	if s.PKCEVerifier() != nil {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("code_verifier", s.PKCEVerifier().Verifier()))
	}
	oauth2Token, err := oauth2Config.Exchange(oidcCtx, authorizationCode, authCodeOpts...)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to exchange auth code with provider: %w", op, p.convertError(err))
	}

	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%s: id_token is missing from auth code exchange: %w", op, ErrMissingIDToken)
	}
	t, err := NewToken(IDToken(idToken), oauth2Token, WithNow(p.config.NowFunc))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create new id_token: %w", op, err)
	}
	claims, err := p.VerifyIDToken(ctx, t.IDToken(), s)
	if err != nil {
		return nil, fmt.Errorf("%s: id_token failed verification: %w", op, err)
	}
	if t.AccessToken() != "" {
		if _, err := t.IDToken().VerifyAccessToken(t.AccessToken()); err != nil {
			return nil, fmt.Errorf("%s: access_token failed verification: %w", op, err)
		}
	}

	// when the optional c_hash claims is present it needs to be verified.
	c_hash, ok := claims["c_hash"].(string)
	if ok && c_hash != "" {
		_, err := t.IDToken().VerifyAuthorizationCode(authorizationCode)
		if err != nil {
			return nil, fmt.Errorf("%s: code hash failed verification: %w", op, err)
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
	oidcCtx, err := p.HTTPClientContext(ctx)
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

// VerifyIDToken will verify the inbound IDToken and return its claims.
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
//   * when max_age was requested, the auth_time claim is verified (with a leeway
//     of 1 min)
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Provider) VerifyIDToken(ctx context.Context, t IDToken, s State, opt ...Option) (map[string]interface{}, error) {
	const op = "Provider.VerifyIDToken"
	if t == "" {
		return nil, fmt.Errorf("%s: id_token is empty: %w", op, ErrInvalidParameter)
	}
	if s.Nonce() == "" {
		return nil, fmt.Errorf("%s: nonce is empty: %w", op, ErrInvalidParameter)
	}
	algs := []string{}
	for _, a := range p.config.SupportedSigningAlgs {
		algs = append(algs, string(a))
	}
	oidcConfig := &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: algs,
		Now:                  p.config.Now,
	}
	verifier := p.provider.Verifier(oidcConfig)
	nowTime := p.config.Now() // intialized right after the Verifier so there idea of nowTime sort of coresponds.
	leeway := 1 * time.Minute

	// verifier.Verify will check the supported algs, signature, iss, exp, nbf.
	// aud will be checked later in this function.
	oidcIDToken, err := verifier.Verify(ctx, string(t))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid id_token: %w", op, p.convertError(err))
	}
	// so.. we still need to check: nonce, iat, auth_time, azp, the aud includes
	// additional audiences configured.
	if oidcIDToken.Nonce != s.Nonce() {
		return nil, fmt.Errorf("%s: invalid id_token nonce: %w", op, ErrInvalidNonce)
	}
	if nowTime.Add(leeway).Before(oidcIDToken.IssuedAt) {
		return nil, fmt.Errorf(
			"%s: invalid id_token current time %v before the iat (issued at) time %v: %w",
			op,
			nowTime,
			oidcIDToken.IssuedAt,
			ErrInvalidIssuedAt,
		)
	}

	var audiences []string
	switch {
	case len(s.Audiences()) > 0:
		audiences = s.Audiences()
	default:
		audiences = p.config.Audiences
	}
	if err := func() error {
		if len(audiences) > 0 {
			for _, v := range audiences {
				if strutils.StrListContains(oidcIDToken.Audience, v) {
					return nil
				}
			}
			return ErrInvalidAudience
		}
		return nil
	}(); err != nil {
		return nil, fmt.Errorf("%s: invalid id_token audiences: %w", op, err)
	}
	if len(oidcIDToken.Audience) > 1 && !strutils.StrListContains(oidcIDToken.Audience, p.config.ClientID) {
		return nil, fmt.Errorf("%s: invalid id_token: multiple audiences (%s) and one of them is not equal client_id (%s): %w", op, oidcIDToken.Audience, p.config.ClientID, ErrInvalidAudience)
	}

	var claims map[string]interface{}
	if err := t.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	azp, foundAzp := claims["azp"]
	if foundAzp {
		if azp != p.config.ClientID {
			return nil, fmt.Errorf("%s: invalid id_token: authorized party (%s) is not equal client_id (%s): %w", op, azp, p.config.ClientID, ErrInvalidAuthorizedParty)
		}
	}
	if len(oidcIDToken.Audience) > 1 && azp != p.config.ClientID {
		return nil, fmt.Errorf("%s: invalid id_token: multiple audiences and authorized party (%s) is not equal client_id (%s): %w", op, azp, p.config.ClientID, ErrInvalidAuthorizedParty)
	}
	if (len(oidcIDToken.Audience) == 1 && oidcIDToken.Audience[0] != p.config.ClientID) && azp != p.config.ClientID {
		return nil, fmt.Errorf(
			"%s: invalid id_token: one audience (%s) which is not the client_id (%s) and authorized party (%s) is not equal client_id (%s): %w",
			op,
			oidcIDToken.Audience[0],
			p.config.ClientID,
			azp,
			p.config.ClientID,
			ErrInvalidAuthorizedParty)
	}

	if secs, authAfter := s.MaxAge(); !authAfter.IsZero() {
		atClaim, ok := claims["auth_time"].(float64)
		if !ok {
			return nil, fmt.Errorf("%s: missing auth_time claim when max age was requested: %w", op, ErrMissingClaim)
		}
		authTime := time.Unix(int64(atClaim), 0)
		if !authTime.Add(leeway).After(authAfter) {
			return nil, fmt.Errorf("%s: auth_time (%s) is beyond max age (%d): %w", op, authTime, secs, ErrExpiredAuthTime)
		}
	}

	return claims, nil
}

// convertError is only used to convert errors from the core-os library calls of:
// provider.Exchange and verifier.Verify.
func (p *Provider) convertError(e error) error {
	switch {
	case strings.Contains(e.Error(), "id token issued by a different provider"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidIssuer)
	case strings.Contains(e.Error(), "signed with unsupported algorithm"):
		return fmt.Errorf("%s: %w", e.Error(), ErrUnsupportedAlg)
	case strings.Contains(e.Error(), "before the nbf (not before) time"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidNotBefore)
	case strings.Contains(e.Error(), "before the iat (issued at) time"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidIssuedAt)
	case strings.Contains(e.Error(), "token is expired"):
		return fmt.Errorf("%s: %w", e.Error(), ErrExpiredToken)
	case strings.Contains(e.Error(), "failed to verify id token signature"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidSignature)
	case strings.Contains(e.Error(), "failed to decode keys"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidJWKs)
	case strings.Contains(e.Error(), "get keys failed"):
		return fmt.Errorf("%s: %w", e.Error(), ErrInvalidJWKs)
	case strings.Contains(e.Error(), "server response missing access_token"):
		return fmt.Errorf("%s: %w", e.Error(), ErrMissingAccessToken)
	default:
		return e
	}
}

// HTTPClient returns an http.Client for the provider. The returned client uses
// a pooled transport (so it can reuse connections) that uses the provider's
// config CA certificate PEM if provided, otherwise it will use the installed
// system CA chain.  This client's idle connections are closed in
// Provider.Done()
func (p *Provider) HTTPClient() (*http.Client, error) {
	const op = "Provider.NewHTTPClient"
	p.mu.Lock()
	defer p.mu.Unlock()
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

// HTTPClientContext returns a new Context that carries the provider's HTTP
// client. This method sets the same context key used by the
// github.com/coreos/go-oidc and golang.org/x/oauth2 packages, so the returned
// context works for those packages as well.
func (p *Provider) HTTPClientContext(ctx context.Context) (context.Context, error) {
	const op = "Provider.HTTPClientContext"
	c, err := p.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)

	}
	// simple to implement as a wrapper for the coreos package
	return oidc.ClientContext(ctx, c), nil
}

// validRedirect checks whether uri is in allowed using special handling for
// loopback uris. Ref: https://tools.ietf.org/html/rfc8252#section-7.3
func (p *Provider) validRedirect(uri string) error {
	const op = "Provider.validRedirect"
	inputURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("redirect URI %s is an invalid URI %s: %w", uri, err.Error(), ErrInvalidParameter)
	}

	// if uri isn't a loopback, just string search the allowed list
	if !strutils.StrListContains([]string{"localhost", "127.0.0.1", "::1"}, inputURI.Hostname()) {
		if !strutils.StrListContains(p.config.AllowedRedirectURLs, uri) {
			return fmt.Errorf("redirect URI %s: %w", uri, ErrUnauthorizedRedirectURI)
		}
	}

	// otherwise, search for a match in a port-agnostic manner, per the OAuth RFC.
	inputURI.Host = inputURI.Hostname()

	for _, a := range p.config.AllowedRedirectURLs {
		allowedURI, err := url.Parse(a)
		if err != nil {
			return fmt.Errorf("allowed redirect URI %s is an invalid URI %s: %w", allowedURI, err.Error(), ErrInvalidParameter)
		}
		allowedURI.Host = allowedURI.Hostname()

		if inputURI.String() == allowedURI.String() {
			return nil
		}
	}
	return fmt.Errorf("redirect URI %s: %w", uri, ErrUnauthorizedRedirectURI)
}
