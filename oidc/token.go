package oidc

import (
	"time"
)

// DefaultTokenExpirySkew defines a default time skew when checking a Token's
// expiration.
const DefaultTokenExpirySkew = 10 * time.Second

// Token represents an Oauth2 access_token and refresh_token (including the the access_token
// expiry), as well as an OIDC id_token
type Token struct {
	RefreshToken string
	AccessToken  string
	Expiry       time.Time
	IdToken      string
}

// Expired will return true if the token is expired.  Supports the
// WithExpirySkew option and if none is provided it will use the
// DefaultTokenExpirySkew.
func (t *Token) Expired(opt ...Option) bool {
	if t.Expiry.IsZero() {
		return false
	}
	opts := getTokenOpts(opt...)
	return t.Expiry.Round(0).Before(time.Now().Add(opts.withExpirySkew))
}

// Valid will ensure that the access_token is not empty or expired.
func (t *Token) Valid() bool {
	if t == nil {
		return false
	}
	if t.AccessToken == "" {
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
