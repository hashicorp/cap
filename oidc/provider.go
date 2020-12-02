package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc"
	strutil "github.com/hashicorp/cap/sdk/strutils"
	"golang.org/x/oauth2"
)

// Provider provides integration with a provider using the typical
// 3-legged OIDC authorization code flow.
type Provider struct {
	config   *Config
	provider *oidc.Provider

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

	client, err := c.HttpClient()
	if err != nil {
		p.Done() // release the backgroundCtxCancel resources
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}

	provider, err := oidc.NewProvider(HttpClientContext(p.backgroundCtx, client), c.Issuer) // makes http req to issuer for discovery
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
}

// AuthURL will generate a URL the caller can use to kick off an OIDC
// authorization code flow with an IdP.  The redirectURL is the URL the IdP
// should use as a redirect after the authentication/authorization is completed
// by the user.
//
//  See NewState() to create an oidc flow State with a valid Id and Nonce that
// will uniquely identify the user's authentication attempt through out the flow.
func (p *Provider) AuthURL(ctx context.Context, s State) (url string, e error) {
	const op = "Provider.AuthURL"
	if s.Id() == s.Nonce() {
		return "", fmt.Errorf("%s: state id and nonce cannot be equal: %w", op, ErrInvalidParameter)
	}
	// Add the "openid" scope, which is a required scope for oidc flows
	scopes := append([]string{oidc.ScopeOpenID}, p.config.Scopes...)

	// Configure an OpenID Connect aware OAuth2 client
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientId,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  p.config.RedirectUrl,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}
	authCodeOpts := []oauth2.AuthCodeOption{
		oidc.Nonce(s.Nonce()),
	}
	return oauth2Config.AuthCodeURL(s.Id(), authCodeOpts...), nil
}

// Exchange will request a token from the oidc token endpoint, using the
// authorizationCode and authorizationState it received in an earlier successful oidc
// authentication response.
//
// It will also validate the authorizationState it receives against the
// existing State for the user's oidc authentication flow.
//
// On success, the Token returned will include IdToken and AccessToken.  Based
// on the IdP, it may include a RefreshToken.  Based on the provider config, it
// may include UserInfoClaims.
func (p *Provider) Exchange(ctx context.Context, s State, authorizationState string, authorizationCode string) (*Tk, error) {
	const op = "Provider.Exchange"
	if p.config == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if s.Id() != authorizationState {
		return nil, fmt.Errorf("%s: authentication state and authorization state are not equal: %w", op, ErrInvalidParameter)
	}
	if s.IsExpired() {
		return nil, fmt.Errorf("%s: authentication state is expired: %w", op, ErrInvalidParameter)
	}

	client, err := p.config.HttpClient()
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}
	oidcCtx := HttpClientContext(ctx, client)

	// Add the "openid" scope, which is a required scope for oidc flows
	// * TODO (jimlambrt 11/2020): make sure these additional scopes work as intended.
	scopes := append([]string{oidc.ScopeOpenID}, p.config.Scopes...)

	var oauth2Config = oauth2.Config{
		ClientID:     p.config.ClientId,
		ClientSecret: string(p.config.ClientSecret),
		RedirectURL:  p.config.RedirectUrl,
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
	t, err := NewToken(IdToken(idToken), oauth2Token)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create new id_token: %w", op, err)
	}
	if err := p.VerifyIdToken(ctx, t.IdToken(), s.Nonce()); err != nil {
		return nil, fmt.Errorf("%s: id_token failed verification: %w", op, err)
	}
	return t, nil
}

// UserInfo gets the UserInfo claims from the provider using the token produced
// by the tokenSource.
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource, claims interface{}) error {
	const op = "Provider.UserInfo"
	if tokenSource == nil {
		return fmt.Errorf("%s: token source is nil: %w", op, ErrInvalidParameter)
	}
	if claims == nil {
		return fmt.Errorf("%s: claims interface is nil: %w", op, ErrNilParameter)
	}
	client, err := p.config.HttpClient()
	if err != nil {
		return fmt.Errorf("%s: unable to create http client: %w", op, err)
	}
	oidcCtx := HttpClientContext(ctx, client)

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

// VerifyIdToken will verify the inbound IdToken.  It verifies it's been signed
// by the provider, it validates the nonce, and performs checks any additional
// checks depending on the provider's config (audiences, etc).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Provider) VerifyIdToken(ctx context.Context, t IdToken, nonce string) error {
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
		ClientID:             p.config.ClientId,
	}
	verifier := p.provider.Verifier(oidcConfig)

	oidcIdToken, err := verifier.Verify(ctx, string(t))
	if err != nil {
		return fmt.Errorf("%s: invalid id_token signature: %w", op, err)
	}

	if oidcIdToken.Nonce != nonce {
		return fmt.Errorf("%s: invalid id_token nonce: %w", op, ErrInvalidNonce)
	}

	if err := func() error {
		if len(p.config.Audiences) > 0 {
			for _, v := range p.config.Audiences {
				if strutil.StrListContains(oidcIdToken.Audience, v) {
					return nil
				}
			}
			return ErrInvalidAudience
		}
		return nil
	}(); err != nil {
		return fmt.Errorf("%s: invalid id_token audiences: %w", op, err)
	}
	return nil
}
