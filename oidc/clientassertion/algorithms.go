// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import (
	"crypto/rsa"
	"fmt"
)

type (
	// HSAlgorithm is an HMAC signature algorithm
	HSAlgorithm string
	// RSAlgorithm is an RSA signature algorithm
	RSAlgorithm string
)

// JOSE asymmetric signing algorithm values as defined by RFC 7518.
// See: https://tools.ietf.org/html/rfc7518#section-3.1
const (
	HS256 HSAlgorithm = "HS256" // HMAC using SHA-256
	HS384 HSAlgorithm = "HS384" // HMAC using SHA-384
	HS512 HSAlgorithm = "HS512" // HMAC using SHA-512
	RS256 RSAlgorithm = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 RSAlgorithm = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 RSAlgorithm = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
)

// Validate checks that the secret is a supported algorithm and that it's
// the proper length for the HSAlgorithm:
//   - HS256: >= 32 bytes
//   - HS384: >= 48 bytes
//   - HS512: >= 64 bytes
func (a HSAlgorithm) Validate(secret string) error {
	const op = "HSAlgorithm.Validate"
	if secret == "" {
		return fmt.Errorf("%s: %w: empty", op, ErrInvalidSecretLength)
	}
	// verify secret length based on alg
	var expectLen int
	switch a {
	case HS256:
		expectLen = 32
	case HS384:
		expectLen = 48
	case HS512:
		expectLen = 64
	default:
		return fmt.Errorf("%s: %w %q for client secret", op, ErrUnsupportedAlgorithm, a)
	}
	if len(secret) < expectLen {
		return fmt.Errorf("%s: %w: %q must be %d bytes long", op, ErrInvalidSecretLength, a, expectLen)
	}
	return nil
}

// Validate checks that the key is a supported algorithm and is valid per
// rsa.PrivateKey's Validate() method.
func (a RSAlgorithm) Validate(key *rsa.PrivateKey) error {
	const op = "RSAlgorithm.Validate"
	if key == nil {
		return fmt.Errorf("%s: %w", op, ErrNilPrivateKey)
	}
	switch a {
	case RS256, RS384, RS512:
		if err := key.Validate(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	default:
		return fmt.Errorf("%s: %w %q for for RSA key", op, ErrUnsupportedAlgorithm, a)
	}
}
