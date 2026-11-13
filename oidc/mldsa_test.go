package oidc

import (
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIDToken_MLDSAHashClaims(t *testing.T) {
	// OpenID Connect Token Hash Algorithm Implementer's Guide, section 3.
	const value = "YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL"
	const expectedHash = "sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3I"

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

			claims := []struct {
				name     string
				verify   func(IDToken, string) (bool, error)
				mismatch error
			}{
				{
					name: "at_hash",
					verify: func(token IDToken, input string) (bool, error) {
						return token.VerifyAccessToken(AccessToken(input))
					},
					mismatch: ErrInvalidAtHash,
				},
				{
					name: "c_hash",
					verify: func(token IDToken, input string) (bool, error) {
						return token.VerifyAuthorizationCode(input)
					},
					mismatch: ErrInvalidCodeHash,
				},
			}
			for _, claim := range claims {
				t.Run(claim.name, func(t *testing.T) {
					tests := []struct {
						name         string
						input        string
						hash         string
						omit         bool
						wantVerified bool
						wantErr      error
					}{
						{
							name:         "published vector",
							input:        value,
							hash:         expectedHash,
							wantVerified: true,
						},
						{
							name:    "changed input",
							input:   value + "x",
							hash:    expectedHash,
							wantErr: claim.mismatch,
						},
						{
							name:    "incorrect hash",
							input:   value,
							hash:    "A" + expectedHash[1:],
							wantErr: claim.mismatch,
						},
						{
							name:  "missing claim",
							input: value,
							omit:  true,
						},
					}
					for _, test := range tests {
						t.Run(test.name, func(t *testing.T) {
							tokenClaims := map[string]interface{}{}
							if !test.omit {
								tokenClaims[claim.name] = test.hash
							}
							raw := TestSignJWT(t, privateKey, string(algorithm.alg), tokenClaims, nil)
							verified, err := claim.verify(IDToken(raw), test.input)
							if test.wantErr != nil {
								require.ErrorIs(t, err, test.wantErr)
							} else {
								require.NoError(t, err)
							}
							require.Equal(t, test.wantVerified, verified)
						})
					}
				})
			}
		})
	}
}
