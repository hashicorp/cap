package oidc

import (
	"context"
	"errors"
	"sync"

	"github.com/coreos/go-oidc"
	strutil "github.com/hashicorp/cap/sdk/strutils"
	"golang.org/x/oauth2"
)

// AuthCodeProvider provides integration with a provider using the typical
// 3-legged OIDC authorization code flow.
type AuthCodeProvider struct {
	config   *AuthCodeConfig
	provider *oidc.Provider

	mu sync.Mutex

	// backgroundCtx is the context used by the provider for background
	// activities like: refreshing JWKs ket sets, refreshing tokens, etc
	backgroundCtx context.Context

	// backgroundCtxCancel is used to cancel any background activities running
	// in spawned go routines.
	backgroundCtxCancel context.CancelFunc
}

// NewAuthCodeProvider creates and initializes a Provider for the OIDC
// authorization code flow.  Intializing the the provider, includes making an
// http request to the provider's issuer.
//
//  See: AuthCodeProvider.Stop() which must be called to release provider resources.
//	See: NewProviderConfig() to create a ProviderConfig.
func NewAuthCodeProvider(c *AuthCodeConfig, opts ...Option) (*AuthCodeProvider, error) {
	const op = "authcode.NewProvider"
	if c == nil {
		return nil, NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("provider config is nil"))
	}
	if err := c.Validate(); err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrParameterViolation), WithMsg("provider config is invalid"), WithWrap(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	// initializing the AuthCodeProvider with it's background ctx/cancel will
	// allow us to use p.Stop() to release any resources when returning errors
	// from this function.
	p := &AuthCodeProvider{
		config:              c,
		backgroundCtx:       ctx,
		backgroundCtxCancel: cancel,
	}

	client, err := c.HttpClient()
	if err != nil {
		p.Done() // release the backgroundCtxCancel resources
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable create http client"))
	}

	provider, err := oidc.NewProvider(HttpClientContext(p.backgroundCtx, client), c.Issuer) // makes http req to issuer for discovery
	if err != nil {
		p.Done() // release the backgroundCtxCancel resources
		// we don't know what's causing the problem, so we won't classify the
		// error with a Kind
		return nil, NewError(ErrInvalidIssuer, WithOp(op), WithMsg("unable to create provider"), WithWrap(err))
	}
	p.provider = provider

	return p, nil
}

// Done with the provider's background resources and must be called for every
// AuthCodeProvider created
func (p *AuthCodeProvider) Done() {
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
func (p *AuthCodeProvider) AuthURL(ctx context.Context, s State, opts ...Option) (url string, e error) {
	const op = "AuthCodeProvider.AuthURL"
	if s.Id() == s.Nonce() {
		return "", NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("state id and nonce cannot be equal"))
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
func (p *AuthCodeProvider) Exchange(ctx context.Context, s State, authorizationState string, authorizationCode string) (*Tk, error) {
	const op = "AuthCodeProvider.Exchange"
	if p.config == nil {
		return nil, NewError(ErrNilParameter, WithOp(op), WithKind(ErrInternal), WithMsg("provider config is nil"))
	}
	if s.Id() != authorizationState {
		return nil, NewError(ErrResponseStateInvalid, WithOp(op), WithKind(ErrParameterViolation), WithMsg("authentication state and authorization state are not equal"))
	}
	if s.IsExpired() {
		return nil, NewError(ErrExpiredState, WithOp(op), WithKind(ErrParameterViolation), WithMsg("authentication state is expired"))
	}

	client, err := p.config.HttpClient()
	if err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable to create http client"))
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
		return nil, NewError(ErrCodeExchangeFailed, WithOp(op), WithKind(ErrInternal), WithMsg("unable to exchange auth code with provider"), WithWrap(err))
	}

	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, NewError(ErrMissingIdToken, WithOp(op), WithKind(ErrInternal), WithMsg("id_token is missing from auth code exchange"), WithWrap(err))
	}
	t, err := NewToken(IdToken(idToken), oauth2Token)
	if err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable to create new id_token"), WithWrap(err))
	}
	if err := p.VerifyIdToken(ctx, t.IdToken(), s.Nonce()); err != nil {
		return nil, NewError(ErrIdTokenVerificationFailed, WithOp(op), WithKind(ErrInternal), WithMsg("id_token failed verification"), WithWrap(err))
	}
	return t, nil
}

// UserInfo gets the UserInfo claims from the provider using the token produced
// by the tokenSource.
func (p *AuthCodeProvider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource, claims interface{}) error {
	const op = "Tk.UserInfo"
	if tokenSource == nil {
		return NewError(ErrNilParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("token source is nil"))
	}
	if claims == nil {
		return NewError(ErrNilParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("claims interface is nil"))
	}
	client, err := p.config.HttpClient()
	if err != nil {
		return WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable to create http client"))
	}
	oidcCtx := HttpClientContext(ctx, client)

	userinfo, err := p.provider.UserInfo(oidcCtx, tokenSource)
	if err != nil {
		return NewError(ErrUserInfoFailed, WithOp(op), WithKind(ErrInternal), WithMsg("provider UserInfo request failed"), WithWrap(err))
	}
	err = userinfo.Claims(&claims)
	if err != nil {
		return NewError(ErrUserInfoFailed, WithOp(op), WithKind(ErrInternal), WithMsg("failed to get UserInfo claims"), WithWrap(err))
	}
	return nil
}

// VerifyIdToken will verify the inbound IdToken.  It verifies it's been signed
// by the provider, it validates the nonce, and performs checks any additional
// checks depending on the provider's config (audiences, etc).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *AuthCodeProvider) VerifyIdToken(ctx context.Context, t IdToken, nonce string) error {
	const op = "AuthCodeProvider.VerifyIdToken"
	if t == "" {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("id_token is empty"))
	}
	if nonce == "" {
		return NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("nonce is empty"))
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
		return NewError(ErrInvalidSignature, WithOp(op), WithKind(ErrIntegrityViolation), WithMsg("invalid id_token signature"), WithWrap(err))
	}

	if oidcIdToken.Nonce != nonce {
		return NewError(ErrInvalidNonce, WithOp(op), WithKind(ErrIntegrityViolation), WithMsg("invalid id_token nonce"), WithWrap(err))
	}

	if err := func() error {
		if len(p.config.Audiences) > 0 {
			for _, v := range p.config.Audiences {
				if strutil.StrListContains(oidcIdToken.Audience, v) {
					return nil
				}
			}
			return errors.New("aud claim does not match configured audiences")
		}
		return nil
	}(); err != nil {
		return NewError(ErrInvalidAudience, WithOp(op), WithKind(ErrIntegrityViolation), WithMsg("invalid id_token audiences"), WithWrap(err))
	}
	return nil
}
