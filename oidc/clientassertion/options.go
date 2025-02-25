package clientassertion

import (
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
)

// Option configures the JWT
type Option func(*JWT)

// WithClientSecret sets a secret and algorithm to sign the JWT with
func WithClientSecret(secret string, alg string) Option {
	return func(j *JWT) {
		j.secret = secret
		j.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithRSAKey sets a private key to sign the JWT with
func WithRSAKey(key *rsa.PrivateKey, alg string) Option {
	return func(j *JWT) {
		j.key = key
		j.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithKeyID sets the "kid" header that OIDC providers use to look up the
// public key to check the signed JWT
func WithKeyID(keyID string) Option {
	return func(j *JWT) {
		j.headers["kid"] = keyID
	}
}

// WithHeaders sets extra JWT headers
func WithHeaders(h map[string]string) Option {
	return func(j *JWT) {
		for k, v := range h {
			j.headers[k] = v
		}
	}
}
