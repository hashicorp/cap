package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// DefaultTokenExpirySkew defines a default time skew when checking a Token's
// expiration.
const DefaultTokenExpirySkew = 10 * time.Second

// Token interface represents an OIDC id_token, as well as an Oauth2
// access_token and refresh_token (including the the access_token expiry)
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

// StaticTokenSource is a single function interface that defines a method to
// create a oauth2.TokenSource that always returns the same token. Because the
// token is never refreshed.  A TokenSource can be used to when calling a
// provider's UserInfo(), among other things
type StaticTokenSource interface {
	StaticTokenSource() oauth2.TokenSource
}

// Tk satisfies the Token interface and represents an Oauth2 access_token and
// refresh_token (including the the access_token expiry), as well as an OIDC
// id_token.  The access_token and refresh_token may be empty.
type Tk struct {
	idToken    IdToken
	underlying *oauth2.Token
}

// ensure that Tk implements the Token interface
var _ Token = (*Tk)(nil)

// NewToken creates a new Token (*Tk).  The IdToken is required and the
// *oauth2.Token may be nil.
func NewToken(i IdToken, t *oauth2.Token) (*Tk, error) {
	// since oauth2 is part of stdlib we're not going to worry about it leaking
	// into our abstraction in this factory
	const op = "NewToken"

	if i == "" {
		return nil, fmt.Errorf("%s: id_token is empty: %w", op, ErrInvalidParameter)

	}
	return &Tk{
		idToken:    i,
		underlying: t,
	}, nil
}

// AccessToken implements the Token.AccessToken() interface function and may
// return an empty AccessToken.
func (t *Tk) AccessToken() AccessToken {
	if t.underlying == nil {
		return ""
	}
	return AccessToken(t.underlying.AccessToken)
}

// RefreshToken implements the Token.RefreshToken() interface function and may
// return an empty RefreshToken
func (t *Tk) RefreshToken() RefreshToken {
	if t.underlying == nil {
		return ""
	}
	return RefreshToken(t.underlying.RefreshToken)
}

// IdToken implements the IdToken.IdToken() interface function
func (t *Tk) IdToken() IdToken { return IdToken(t.idToken) }

// Expiry implements the Token.Expiry() interface function and may return a
// "zero" time if the token's AccessToken is empty
func (t *Tk) Expiry() time.Time {
	if t.underlying == nil {
		return time.Time{}
	}
	return t.underlying.Expiry
}

// StaticTokenSource returns a TokenSource that always returns the same token.
// Because the provided token t is never refreshed.  It will return nil, if the
// t.AccessToken() is empty.
func (t *Tk) StaticTokenSource() oauth2.TokenSource {
	if t.underlying == nil {
		return nil
	}
	return oauth2.StaticTokenSource(t.underlying)
}

// Expired will return true if the token is expired.  Supports the
// WithExpirySkew option and if none is provided it will use the
// DefaultTokenExpirySkew.  It returns false if t.AccessToken() is empty.
func (t *Tk) Expired(opt ...Option) bool {
	if t.underlying == nil {
		return true
	}
	if t.underlying.Expiry.IsZero() {
		return false
	}
	opts := getTokenOpts(opt...)
	return t.underlying.Expiry.Round(0).Before(time.Now().Add(opts.withExpirySkew))
}

// Valid will ensure that the access_token is not empty or expired. It will
// return false if t.AccessToken() is empty
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

// Claims retrieves the IdToken claims.
func (t IdToken) Claims(claims interface{}) error {
	const op = "IdToken.Claims"
	if len(t) == 0 {
		return fmt.Errorf("%s: id_token is empty: %w", op, ErrInvalidParameter)
	}
	if claims == nil {
		return fmt.Errorf("%s: claims interface is nil: %w", op, ErrNilParameter)
	}
	return UnmarshalClaims(string(t), claims)
}

// UnmarshalClaims will retrieve the claims from the provided raw JWT token.
func UnmarshalClaims(rawToken string, claims interface{}) error {
	const op = "JwtClaims"
	parts := strings.Split(string(rawToken), ".")
	if len(parts) != 3 {
		return fmt.Errorf("%s: malformed jwt, expected 3 parts got %d: %w", op, len(parts), ErrInvalidParameter)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%s: malformed jwt claims: %w", op, err)
	}
	if err := json.Unmarshal(raw, claims); err != nil {
		return fmt.Errorf("%s: unable to marshal jwt JSON: %w", op, err)
	}
	return nil
}
