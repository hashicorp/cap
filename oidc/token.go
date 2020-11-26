package oidc

import (
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

// DefaultTokenExpirySkew defines a default time skew when checking a Token's
// expiration.
const DefaultTokenExpirySkew = 10 * time.Second

// AccessToken is an oauth access_token
type AccessToken string

// RedactedAccessToken is the redacted string or json for an oauth access_token
const RedactedAccessToken = "[REDACTED: access_token]"

// String will redact the token
func (t AccessToken) String() string {
	return RedactedAccessToken
}

// MarshalJSON will redact the token
func (t AccessToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedAccessToken)
}

// RefreshToken is an oauth refresh_token
type RefreshToken string

// RedactedRefreshToken is the redacted string or json for an oauth refresh_token
const RedactedRefreshToken = "[REDACTED: refresh_token]"

// String will redact the token
func (t RefreshToken) String() string {
	return RedactedRefreshToken
}

// MarshalJSON will redact the token
func (t RefreshToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedRefreshToken)
}

// IdToken is an oidc id_token
type IdToken string

// RedactedIdToken is the redacted string or json for an oidc id_token
const RedactedIdToken = "[REDACTED: id_token]"

// String will redact the token
func (t IdToken) String() string {
	return RedactedIdToken
}

// MarshalJSON will redact the token
func (t IdToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedIdToken)
}

// Token interface and represents an Oauth2 access_token and refresh_token
// (including the the access_token expiry), as well as an OIDC id_token
type Token interface {
	// RefreshToken returns the Token's refresh_token
	RefreshToken() RefreshToken

	// AccessToken returns the Token's access_token
	AccessToken() AccessToken

	// IdToken returns the Token's id_token
	IdToken() IdToken

	// Expiry returns the expiration of the access_token
	Expiry() time.Time

	// Valid will ensure that the access_token is not empty or expired.
	Valid() bool

	// Expired will return true if the token is expired.  Implementations may
	// want to support the WithExpirySkew option.
	Expired(opt ...Option) bool
}

// Tk satisfies the Token interface and represents an Oauth2 access_token and
// refresh_token (including the the access_token expiry), as well as an OIDC id_token
type Tk struct {
	idToken    IdToken
	underlying *oauth2.Token
}

// NewToken creates a new Token.
func NewToken(i IdToken, t *oauth2.Token) (Token, error) {
	// since oauth2 is part of stdlib we're not going to worry about it leaking
	// into our abstraction in this factory
	const op = "oidc.NewToken"
	if t == nil {
		return nil, NewError(ErrNilParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("token is nil"))
	}
	if i == "" {
		return nil, NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("id_token is empty"))
	}
	return &Tk{
		idToken:    i,
		underlying: t,
	}, nil
}

func (t *Tk) AccessToken() AccessToken   { return AccessToken(t.underlying.AccessToken) }
func (t *Tk) RefreshToken() RefreshToken { return RefreshToken(t.underlying.RefreshToken) }
func (t *Tk) IdToken() IdToken           { return IdToken(t.idToken) }
func (t *Tk) Expiry() time.Time          { return t.underlying.Expiry }

// StaticTokenSource returns a TokenSource that always returns the same token.
// Because the provided token t is never refreshed.
func (t *Tk) StaticTokenSource() oauth2.TokenSource {
	return oauth2.StaticTokenSource(t.underlying)
}

// Expired will return true if the token is expired.  Supports the
// WithExpirySkew option and if none is provided it will use the
// DefaultTokenExpirySkew.
func (t *Tk) Expired(opt ...Option) bool {
	if t.underlying.Expiry.IsZero() {
		return false
	}
	opts := getTokenOpts(opt...)
	return t.underlying.Expiry.Round(0).Before(time.Now().Add(opts.withExpirySkew))
}

// Valid will ensure that the access_token is not empty or expired.
func (t *Tk) Valid() bool {
	if t == nil {
		return false
	}
	if t.underlying.AccessToken == "" {
		return false
	}
	return !t.Expired()
}

// tokenOptions is the set of available options for Token functions
type tokenOptions struct {
	withExpirySkew time.Duration
}

// tokenDefaults is a handy way to get the defaults at runtime and during unit
// tests.
func tokenDefaults() tokenOptions {
	return tokenOptions{
		withExpirySkew: DefaultTokenExpirySkew,
	}
}

// getTokenOpts gets the token defaults and applies the opt overrides passed
// in
func getTokenOpts(opt ...Option) tokenOptions {
	opts := tokenDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}
