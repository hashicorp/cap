// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import "github.com/go-jose/go-jose/v4"

// Alg represents asymmetric signing algorithms
type Alg string

const (
	// JOSE asymmetric signing algorithm values as defined by RFC 7518.
	//
	// See: https://tools.ietf.org/html/rfc7518#section-3.1
	// ML-DSA identifiers are defined by https://datatracker.ietf.org/doc/rfc9964/.
	RS256   Alg = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384   Alg = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512   Alg = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256   Alg = "ES256" // ECDSA using P-256 and SHA-256
	ES384   Alg = "ES384" // ECDSA using P-384 and SHA-384
	ES512   Alg = "ES512" // ECDSA using P-521 and SHA-512
	PS256   Alg = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384   Alg = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512   Alg = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	EdDSA   Alg = "EdDSA"
	MLDSA44 Alg = "ML-DSA-44" // ML-DSA-44 (FIPS 204, RFC 9964)
	MLDSA65 Alg = "ML-DSA-65" // ML-DSA-65 (FIPS 204, RFC 9964)
	MLDSA87 Alg = "ML-DSA-87" // ML-DSA-87 (FIPS 204, RFC 9964)
)

var supportedAlgorithms = map[Alg]bool{
	RS256:   true,
	RS384:   true,
	RS512:   true,
	ES256:   true,
	ES384:   true,
	ES512:   true,
	PS256:   true,
	PS384:   true,
	PS512:   true,
	EdDSA:   true,
	MLDSA44: true,
	MLDSA65: true,
	MLDSA87: true,
}

func joseSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := make([]jose.SignatureAlgorithm, 0, len(supportedAlgorithms))
	for algorithm := range supportedAlgorithms {
		algorithms = append(algorithms, jose.SignatureAlgorithm(algorithm))
	}
	return algorithms
}
