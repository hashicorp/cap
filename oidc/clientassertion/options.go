// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import (
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// KeyIDHeader is the "kid" header on a JWT, which providers use to look up
// the right public key to verify the JWT.
const KeyIDHeader = "kid"

// Option configures the JWT
type Option func(*JWT) error

// WithClientSecret sets a secret and algorithm to sign the JWT with.
// alg must be one of:
// * HS256 with a >= 32 byte secret
// * HS384 with a >= 48 byte secret
// * HS512 with a >= 64 byte secret
func WithClientSecret(secret string, alg HSAlgorithm) Option {
	return func(j *JWT) error {
		if err := alg.Validate(secret); err != nil {
			return err
		}
		j.secret = secret
		j.alg = jose.SignatureAlgorithm(alg)
		return nil
	}
}

// WithRSAKey sets a private key to sign the JWT with.
// alg must be one of:
// * RS256
// * RS384
// * RS512
func WithRSAKey(key *rsa.PrivateKey, alg RSAlgorithm) Option {
	const op = "WithRSAKey"
	return func(j *JWT) error {
		if err := alg.Validate(key); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		j.key = key
		j.alg = jose.SignatureAlgorithm(alg)
		return nil
	}
}

// WithKeyID sets the "kid" header that OIDC providers use to look up the
// public key to check the signed JWT
func WithKeyID(keyID string) Option {
	const op = "WithKeyID"
	return func(j *JWT) error {
		if keyID == "" {
			return fmt.Errorf("%s: %w", op, ErrMissingKeyID)
		}
		j.headers["kid"] = keyID
		return nil
	}
}

// WithHeaders sets extra JWT headers.
// Do not set a "kid" header here; instead use WithKeyID.
func WithHeaders(h map[string]string) Option {
	const op = "WithHeaders"
	return func(j *JWT) error {
		for k, v := range h {
			if k == KeyIDHeader {
				return fmt.Errorf(`%s: "kid" header not allowed; use WithKeyID instead`, op)
			}
			j.headers[k] = v
		}
		return nil
	}
}
