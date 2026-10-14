// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/oidc"
)

func TestValidator_TimeClaimPresence(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	epoch := time.Unix(0, 0)
	nowUnix := float64(now.Unix())
	future := float64(now.Add(time.Hour).Unix())
	earlierStart := float64(now.Add(-4 * time.Minute).Unix())
	laterStart := float64(now.Add(-time.Minute).Unix())
	beforeEpoch := epoch.Add(-10 * time.Minute)
	const (
		expired     = "invalid expiration time (exp) claim: token is expired"
		notYetValid = "invalid not before (nbf) claim: token not yet valid"
	)

	keySet, err := NewStaticKeySet([]crypto.PublicKey{priv.Public()})
	require.NoError(t, err)
	validator, err := NewValidator(keySet)
	require.NoError(t, err)

	tests := []struct {
		name    string
		claims  map[string]interface{}
		now     time.Time
		wantErr string
	}{
		{
			name:   "explicit epoch start claims with future expiration",
			claims: map[string]interface{}{"iat": 0.0, "nbf": 0.0, "exp": future},
			now:    now,
		},
		{
			name:   "explicit epoch not before without issued at",
			claims: map[string]interface{}{"nbf": 0.0, "exp": future},
			now:    now,
		},
		{
			name:   "derive not before from explicit epoch issued at",
			claims: map[string]interface{}{"iat": 0.0, "exp": future},
			now:    now,
		},
		{
			name:    "zero expiration stays zero and jwt is expired",
			claims:  map[string]interface{}{"iat": nowUnix, "nbf": nowUnix, "exp": 0.0},
			now:     now,
			wantErr: expired,
		},
		{
			name:    "all epoch claims are present and expired",
			claims:  map[string]interface{}{"iat": 0.0, "nbf": 0.0, "exp": 0.0},
			now:     now,
			wantErr: expired,
		},
		{
			name:   "all epoch claims are valid at epoch",
			claims: map[string]interface{}{"iat": 0.0, "nbf": 0.0, "exp": 0.0},
			now:    epoch,
		},
		{
			name:   "derive expiration from epoch issued at",
			claims: map[string]interface{}{"iat": 0.0},
			now:    epoch.Add(100 * time.Second),
		},
		{
			name:   "derive expiration from epoch not before",
			claims: map[string]interface{}{"nbf": 0.0},
			now:    epoch.Add(100 * time.Second),
		},
		{
			name:    "derived expiration from epoch issued at is expired",
			claims:  map[string]interface{}{"iat": 0.0},
			now:     now,
			wantErr: expired,
		},
		{
			name:   "explicit epoch expiration without start claims",
			claims: map[string]interface{}{"exp": 0.0},
			now:    epoch,
		},
		{
			name:   "pre-epoch not before without issued at is valid",
			claims: map[string]interface{}{"nbf": float64(beforeEpoch.Unix())},
			now:    beforeEpoch.Add(time.Minute),
		},
		{
			name:    "pre-epoch not before without issued at is expired",
			claims:  map[string]interface{}{"nbf": float64(beforeEpoch.Unix())},
			now:     epoch,
			wantErr: expired,
		},
		{
			name:   "derive expiration from later not before",
			claims: map[string]interface{}{"iat": earlierStart, "nbf": laterStart},
			now:    now,
		},
		{
			name:   "derive expiration from later issued at",
			claims: map[string]interface{}{"iat": laterStart, "nbf": earlierStart},
			now:    now,
		},
		{
			name:    "omitted start claims still derive not before",
			claims:  map[string]interface{}{"exp": future},
			now:     now,
			wantErr: notYetValid,
		},
		{
			name:    "null start claims still derive not before",
			claims:  map[string]interface{}{"iat": nil, "nbf": nil, "exp": future},
			now:     now,
			wantErr: notYetValid,
		},
	}

	methods := []struct {
		name     string
		validate func(context.Context, string, Expected) (map[string]interface{}, error)
	}{
		{name: "Validate", validate: validator.Validate},
		{name: "ValidateAllowMissingIatNbfExp", validate: validator.ValidateAllowMissingIatNbfExp},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := oidc.TestSignJWT(t, priv, string(RS256), tt.claims, []byte(testKeyID))
			expected := Expected{Now: func() time.Time { return tt.now }}
			for _, method := range methods {
				t.Run(method.name, func(t *testing.T) {
					got, err := method.validate(context.Background(), token, expected)
					if tt.wantErr != "" {
						require.EqualError(t, err, tt.wantErr)
						require.Nil(t, got)
						return
					}
					require.NoError(t, err)
					require.Equal(t, tt.claims, got)
				})
			}
		})
	}
}

func TestValidator_MissingTimeClaims(t *testing.T) {
	keySet, err := NewStaticKeySet([]crypto.PublicKey{priv.Public()})
	require.NoError(t, err)
	validator, err := NewValidator(keySet)
	require.NoError(t, err)

	tests := []struct {
		name   string
		claims map[string]interface{}
	}{
		{name: "omitted", claims: map[string]interface{}{"sub": "test"}},
		{name: "null", claims: map[string]interface{}{"iat": nil, "nbf": nil, "exp": nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := oidc.TestSignJWT(t, priv, string(RS256), tt.claims, []byte(testKeyID))

			t.Run("Validate", func(t *testing.T) {
				got, err := validator.Validate(context.Background(), token, Expected{})
				require.EqualError(t, err, "no issued at (iat), not before (nbf), or expiration time (exp) claims in token")
				require.Nil(t, got)
			})
			t.Run("ValidateAllowMissingIatNbfExp", func(t *testing.T) {
				got, err := validator.ValidateAllowMissingIatNbfExp(context.Background(), token, Expected{})
				require.NoError(t, err)
				require.Equal(t, tt.claims, got)
			})
		})
	}
}
