package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Token interface represents an OIDC id_token, as well as an Oauth2
// access_token and refresh_token (including the the access_token expiry).
type Token interface {
	// RefreshToken returns the Token's refresh_token.
	RefreshToken() RefreshToken

	// AccessToken returns the Token's access_token.
	AccessToken() AccessToken

	// IDToken returns the Token's id_token.
	IDToken() IDToken

	// Expiry returns the expiration of the access_token.
	Expiry() time.Time

	// Valid will ensure that the access_token is not empty or expired.
	Valid() bool

	// IsExpired returns true if the token has expired. Implementations should
	// support a time skew (perhaps TokenExpirySkew) when checking expiration.
	IsExpired() bool
}

// StaticTokenSource is a single function interface that defines a method to
// create a oauth2.TokenSource that always returns the same token. Because the
// token is never refreshed.  A TokenSource can be used to when calling a
// provider's UserInfo(), among other things.
type StaticTokenSource interface {
	StaticTokenSource() oauth2.TokenSource
}

// Tk satisfies the Token interface and represents an Oauth2 access_token and
// refresh_token (including the the access_token expiry), as well as an OIDC
// id_token.  The access_token and refresh_token may be empty.
type Tk struct {
	idToken    IDToken
	underlying *oauth2.Token
}

// ensure that Tk implements the Token interface.
var _ Token = (*Tk)(nil)

// NewToken creates a new Token (*Tk).  The IDToken is required and the
// *oauth2.Token may be nil.
func NewToken(i IDToken, t *oauth2.Token) (*Tk, error) {
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
// return an empty RefreshToken.
func (t *Tk) RefreshToken() RefreshToken {
	if t.underlying == nil {
		return ""
	}
	return RefreshToken(t.underlying.RefreshToken)
}

// IDToken implements the IDToken.IDToken() interface function.
func (t *Tk) IDToken() IDToken { return IDToken(t.idToken) }

// TokenExpirySkew defines a time skew when checking a Token's expiration.
const TokenExpirySkew = 10 * time.Second

// Expiry implements the Token.Expiry() interface function and may return a
// "zero" time if the token's AccessToken is empty.
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

// IsExpired will return true if the token's access token is expired or empty.
func (t *Tk) IsExpired() bool {
	if t.underlying == nil {
		return true
	}
	if t.underlying.Expiry.IsZero() {
		return false
	}
	return t.underlying.Expiry.Round(0).Before(time.Now().Add(TokenExpirySkew))
}

// Valid will ensure that the access_token is not empty or expired. It will
// return false if t.AccessToken() is empty.
func (t *Tk) Valid() bool {
	if t == nil || t.underlying == nil {
		return false
	}
	if t.underlying.AccessToken == "" {
		return false
	}
	return !t.IsExpired()
}

// UnmarshalClaims will retrieve the claims from the provided raw JWT token.
func UnmarshalClaims(rawToken string, claims interface{}) error {
	const op = "UnmarshalClaims"
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
