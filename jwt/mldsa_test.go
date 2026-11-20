package jwt

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
)

func TestValidator_MLDSA(t *testing.T) {
	algorithms := []struct {
		alg    Alg
		params mldsa.Parameters
	}{
		{MLDSA44, mldsa.MLDSA44()},
		{MLDSA65, mldsa.MLDSA65()},
		{MLDSA87, mldsa.MLDSA87()},
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm.alg), func(t *testing.T) {
			privateKey, err := mldsa.GenerateKey(algorithm.params)
			require.NoError(t, err)
			wrongKey, err := mldsa.GenerateKey(algorithm.params)
			require.NoError(t, err)

			validatorFor := func(publicKey crypto.PublicKey) *Validator {
				keySet, err := NewStaticKeySet([]crypto.PublicKey{publicKey})
				require.NoError(t, err)
				validator, err := NewValidator(keySet)
				require.NoError(t, err)
				return validator
			}
			validator := validatorFor(privateKey.Public())

			now := time.Unix(1800000000, 0)
			claims := map[string]interface{}{
				"iss": "https://example.com/",
				"sub": "alice@example.com",
				"aud": []string{"cap-tests"},
				"iat": now.Add(-time.Minute).Unix(),
				"nbf": now.Add(-time.Minute).Unix(),
				"exp": now.Add(time.Hour).Unix(),
			}
			expected := Expected{
				Issuer:            "https://example.com/",
				Subject:           "alice@example.com",
				Audiences:         []string{"cap-tests"},
				SigningAlgorithms: []Alg{algorithm.alg},
				ClockSkewLeeway:   -time.Second,
				Now:               func() time.Time { return now },
			}
			token := oidc.TestSignJWT(t, privateKey, string(algorithm.alg), claims, nil)

			changedClaims := maps.Clone(claims)
			changedClaims["sub"] = "mallory"
			payload, err := json.Marshal(changedClaims)
			require.NoError(t, err)
			payloadParts := strings.Split(token, ".")
			require.Len(t, payloadParts, 3)
			payloadParts[1] = base64.RawURLEncoding.EncodeToString(payload)

			signatureParts := strings.Split(token, ".")
			signature, err := base64.RawURLEncoding.DecodeString(signatureParts[2])
			require.NoError(t, err)
			require.NotEmpty(t, signature)
			signature[0] ^= 1
			signatureParts[2] = base64.RawURLEncoding.EncodeToString(signature)

			expiredClaims := maps.Clone(claims)
			expiredClaims["iat"] = now.Add(-2 * time.Hour).Unix()
			expiredClaims["nbf"] = now.Add(-2 * time.Hour).Unix()
			expiredClaims["exp"] = now.Add(-time.Hour).Unix()
			expiredToken := oidc.TestSignJWT(t, privateKey, string(algorithm.alg), expiredClaims, nil)

			disallowed := expected
			disallowed.SigningAlgorithms = []Alg{RS256}

			tests := []struct {
				name          string
				token         string
				validator     *Validator
				expected      Expected
				errorContains string
			}{
				{"valid", token, validator, expected, ""},
				{"wrong key", token, validatorFor(wrongKey.Public()), expected, "error verifying token signature"},
				{"modified payload", strings.Join(payloadParts, "."), validator, expected, "error verifying token signature"},
				{"modified signature", strings.Join(signatureParts, "."), validator, expected, "error verifying token signature"},
				{"disallowed algorithm", token, validator, disallowed, "token signed with unexpected algorithm"},
				{"expired", expiredToken, validator, expected, "token is expired"},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					got, err := test.validator.Validate(context.Background(), test.token, test.expected)
					if test.errorContains != "" {
						require.ErrorContains(t, err, test.errorContains)
						return
					}
					require.NoError(t, err)
					require.Equal(t, "alice@example.com", got["sub"])
					require.Equal(t, "https://example.com/", got["iss"])
				})
			}
		})
	}
}
