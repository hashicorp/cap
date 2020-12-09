package oidc

import (
	"encoding/json"
	"fmt"
)

// IDToken is an oidc id_token
// See https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
type IDToken string

// RedactedIDToken is the redacted string or json for an oidc id_token
const RedactedIDToken = "[REDACTED: id_token]"

// String will redact the token
func (t IDToken) String() string {
	return RedactedIDToken
}

// MarshalJSON will redact the token
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
