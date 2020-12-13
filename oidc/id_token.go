package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"gopkg.in/square/go-jose.v2"
)

// IDToken is an oidc id_token.
// See https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
type IDToken string

// RedactedIDToken is the redacted string or json for an oidc id_token.
const RedactedIDToken = "[REDACTED: id_token]"

// String will redact the token.
func (t IDToken) String() string {
	return RedactedIDToken
}

// MarshalJSON will redact the token.
func (t IDToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedIDToken)
}

// Claims retrieves the IDToken claims.
func (t IDToken) Claims(claims interface{}) error {
	const op = "IDToken.Claims"
	if len(t) == 0 {
		return fmt.Errorf("%s: id_token is empty: %w", op, ErrInvalidParameter)
	}
	if claims == nil {
		return fmt.Errorf("%s: claims interface is nil: %w", op, ErrNilParameter)
	}
	return UnmarshalClaims(string(t), claims)
}

// VerifyAccessToken verifies that the hash of the access_token  matches the
// hash in the id_token. It returns an error if the hashes don't match.
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
//
// Returns nil when the optional access_token hash is not present in the in
// the id_token.
//
// Returns nil when the id_token's signing algorithm is EdDSA, since the hash
// cannot be verified without knowing the key's curve
// See: https://bitbucket.org/openid/connect/issues/1125
//
func (t IDToken) VerifyAccessToken(accessToken AccessToken) error {
	const op = "VerifyAccessToken"
	var claims map[string]interface{}
	if err := t.Claims(&claims); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	atHash, ok := claims["at_hash"]
	if !ok {
		return nil
	}

	jws, err := jose.ParseSigned(string(t))
	if err != nil {
		return fmt.Errorf("%s: malformed jwt (%v): %w", op, err, ErrMalformedToken)
	}
	switch len(jws.Signatures) {
	case 0:
		return fmt.Errorf("%s: id_token not signed: %w", op, ErrTokenNotSigned)
	case 1:
	default:
		return fmt.Errorf("%s: multiple signatures on id_token not supported", op)
	}

	sig := jws.Signatures[0]
	if _, ok := supportedAlgorithms[Alg(sig.Header.Algorithm)]; !ok {
		return fmt.Errorf("%s: id_token signed with algorithm %q: %w", op, sig.Header.Algorithm, ErrUnsupportedAlg)
	}

	sigAlgorithm := Alg(sig.Header.Algorithm)

	var h hash.Hash
	switch sigAlgorithm {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512:
		h = sha512.New()
	case EdDSA:
		return nil
	default:
		return fmt.Errorf("%s: unsupported signing algorithm %s: %w", op, sigAlgorithm, ErrUnsupportedAlg)
	}
	_, _ = h.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != atHash {
		return ErrInvalidAtHash
	}
	return nil
}
