// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/oidc"
)

var (
	priv  *rsa.PrivateKey
	priv2 *rsa.PrivateKey
)

func init() {
	// Generate a key to sign JWTs with throughout most test cases.
	// It can be slow sometimes to generate a 4096-bit RSA key, so we only
	// generate the test keys once on initialization.
	var err error
	priv, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	priv2, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
}

// TestValidator_Validate_Valid_JWT tests cases where a JWT is expected to be valid.
func TestValidator_Validate_Valid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	// Create the KeySet to be used to verify JWT signatures
	keySet, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	// Establish past, now, and future for validation of time related claims
	now := time.Now()
	nowUnix := float64(now.Unix())
	pastUnix := float64(now.Add(-2 * jwt.DefaultLeeway).Unix())
	futureUnix := float64(now.Add(2 * jwt.DefaultLeeway).Unix())

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "valid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
		{
			name: "valid jwt with assertion on subject claim",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Subject: "alice@example.com",
				},
			},
		},
		{
			name: "valid jwt with assertion on id claim",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					ID: "abc123",
				},
			},
		},
		{
			name: "valid jwt with assertion on audience claim",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.example.com", "www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Audiences: []string{"www.example.com", "www.other.com"},
				},
			},
		},
		{
			name: "valid jwt with assertion on algorithm header parameter",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS512), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS512},
				},
			},
		},
		{
			name: "valid jwt with assertions on all expected claims",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer:            "https://example.com/",
					Subject:           "alice@example.com",
					ID:                "abc123",
					Audiences:         []string{"www.example.com"},
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "valid jwt with registered claims assertions skipped when empty",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{},
			},
		},
		{
			name: "valid jwt exp after exp leeway set",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT exp would be invalid with exp leeway < 2 min
					ExpirationLeeway: 2 * time.Minute,
					ClockSkewLeeway:  -1,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after nbf leeway set",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT nbf would be invalid with nbf leeway < 2 min
					NotBeforeLeeway: 2 * time.Minute,
					ClockSkewLeeway: -1,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT nbf would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt exp after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": pastUnix,
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT exp would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt iat after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"nbf": pastUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT iat would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			validator, err := NewValidator(keySet)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := validator.Validate(ctx, token, tt.args.expected)

			// Expect to get back the same claims that were serialized in the JWT
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.args.claims, got)
		})
	}
}

func TestValidator_NoExpIatNbf(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	// Create the KeySet to be used to verify JWT signatures
	keySet, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "valid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			validator, err := NewValidator(keySet)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := validator.ValidateAllowMissingIatNbfExp(ctx, token, tt.args.expected)

			// Expect to get back the same claims that were serialized in the JWT
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.args.claims, got)
		})
	}
}

// TestValidator_Validate_Valid_JWT tests cases where a JWT is expected to be invalid.
func TestValidator_Validate_Invalid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	// Create the KeySet to be used to verify JWT signatures
	keySet, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	// Establish past, now, and future for validation of time related claims
	now := time.Now()
	nowUnix := float64(now.Unix())
	pastUnix := float64(now.Add(-2 * jwt.DefaultLeeway).Unix())
	futureUnix := float64(now.Add(2 * jwt.DefaultLeeway).Unix())

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "invalid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://wrong.com/",
				},
			},
		},
		{
			name: "invalid jwt with assertion on subject claim",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Subject: "bob@example.com",
				},
			},
		},
		{
			name: "invalid jwt with assertion on id claim",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					ID: "123abc",
				},
			},
		},
		{
			name: "invalid jwt with assertion on audience claim",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Audiences: []string{"www.example.com"},
				},
			},
		},
		{
			name: "invalid jwt with assertion on algorithm header parameter",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{ES256},
				},
			},
		},
		{
			name: "invalid jwt from failed signature verification",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					// Sign the JWT with a key not in the test provider
					pk, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					return oidc.TestSignJWT(t, pk, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "invalid jwt with missing iat, nbf, and exp claims",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{},
			},
		},
		{
			name: "invalid jwt with now before nbf",
			args: args{
				claims: map[string]interface{}{
					"nbf": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now after exp",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now before iat",
			args: args{
				claims: map[string]interface{}{
					"nbf": pastUnix,
					"iat": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(nowUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid malformed jwt",
			args: args{
				token: func(claims map[string]interface{}) string {
					return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			validator, err := NewValidator(keySet)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := validator.Validate(ctx, token, tt.args.expected)

			// Expect an error and nil claims
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}

func TestNewValidator(t *testing.T) {
	type args struct {
		keySets func() []KeySet
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "new validator with keySet",
			args: args{
				keySets: func() []KeySet {
					ks, err := NewJSONWebKeySet(context.Background(),
						"https://issuer.com/"+wellKnownJWKS, "")
					require.NoError(t, err)
					return []KeySet{ks}
				},
			},
		},
		{
			name: "new validator with nil keySet",
			args: args{
				keySets: func() []KeySet {
					return nil
				},
			},
			wantErr: true,
		},
		{
			name: "new validator with multiple keySets",
			args: args{
				keySets: func() []KeySet {
					ks, err := NewJSONWebKeySet(context.Background(),
						"https://issuer.com/"+wellKnownJWKS, "")
					require.NoError(t, err)

					ks2, err := NewJSONWebKeySet(context.Background(),
						"https://issuer2.com/"+wellKnownJWKS, "")
					return []KeySet{ks, ks2}
				},
			},
		},
		{
			name: "new validator with nil keySet in keySets",
			args: args{
				keySets: func() []KeySet {
					ks, err := NewJSONWebKeySet(context.Background(),
						"https://issuer.com/"+wellKnownJWKS, "")
					require.NoError(t, err)
					return []KeySet{ks, nil}
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewValidator(tt.args.keySets()...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

// TestValidator_MultipleKeySets_Validate_Valid_JWT tests cases where a JWT is expected to be valid where the
// validator is initialized with multiple KeySets.
func TestValidator_MultipleKeySets_Validate_Valid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t, oidc.WithTestPort(8181))
	tp2 := oidc.StartTestProvider(t, oidc.WithTestPort(8182))

	// Create the KeySet to be used to verify JWT signatures
	keySet1, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	keySet2, err := NewOIDCDiscoveryKeySet(context.Background(), tp2.Addr(), tp2.CACert())
	require.NoError(t, err)

	testKeyID2 := fmt.Sprintf("%s-2", testKeyID)
	tp2.SetSigningKeys(priv, priv2.Public(), oidc.RS256, testKeyID2)

	// Establish past, now, and future for validation of time related claims
	now := time.Now()
	nowUnix := float64(now.Unix())
	pastUnix := float64(now.Add(-2 * jwt.DefaultLeeway).Unix())
	futureUnix := float64(now.Add(2 * jwt.DefaultLeeway).Unix())

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "valid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
		{
			name: "valid jwt with assertion on issuer claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
		{
			name: "valid jwt with assertion on subject claim",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Subject: "alice@example.com",
				},
			},
		},
		{
			name: "valid jwt with assertion on subject claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Subject: "alice@example.com",
				},
			},
		},
		{
			name: "valid jwt with assertion on id claim",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					ID: "abc123",
				},
			},
		},
		{
			name: "valid jwt with assertion on id claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					ID: "abc123",
				},
			},
		},
		{
			name: "valid jwt with assertion on audience claim",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.example.com", "www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Audiences: []string{"www.example.com", "www.other.com"},
				},
			},
		},
		{
			name: "valid jwt with assertion on audience claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.example.com", "www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Audiences: []string{"www.example.com", "www.other.com"},
				},
			},
		},
		{
			name: "valid jwt with assertion on algorithm header parameter",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS512), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS512},
				},
			},
		},
		{
			name: "valid jwt with assertion on algorithm header parameter from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS512), claims, []byte(testKeyID2))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS512},
				},
			},
		},
		{
			name: "valid jwt with assertions on all expected claims",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer:            "https://example.com/",
					Subject:           "alice@example.com",
					ID:                "abc123",
					Audiences:         []string{"www.example.com"},
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "valid jwt with assertions on all expected claims from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Issuer:            "https://example.com/",
					Subject:           "alice@example.com",
					ID:                "abc123",
					Audiences:         []string{"www.example.com"},
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "valid jwt with registered claims assertions skipped when empty",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{},
			},
		},
		{
			name: "valid jwt with registered claims assertions skipped when empty from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"sub": "alice@example.com",
					"jti": "abc123",
					"aud": []interface{}{"www.example.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{},
			},
		},
		{
			name: "valid jwt exp after exp leeway set",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT exp would be invalid with exp leeway < 2 min
					ExpirationLeeway: 2 * time.Minute,
					ClockSkewLeeway:  -1,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt exp after exp leeway set from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					// The JWT exp would be invalid with exp leeway < 2 min
					ExpirationLeeway: 2 * time.Minute,
					ClockSkewLeeway:  -1,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after nbf leeway set",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT nbf would be invalid with nbf leeway < 2 min
					NotBeforeLeeway: 2 * time.Minute,
					ClockSkewLeeway: -1,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after nbf leeway set from key set 2",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					// The JWT nbf would be invalid with nbf leeway < 2 min
					NotBeforeLeeway: 2 * time.Minute,
					ClockSkewLeeway: -1,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT nbf would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt nbf after clock skew leeway from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					// The JWT nbf would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt exp after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": pastUnix,
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT exp would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt exp after clock skew leeway from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": pastUnix,
					"nbf": pastUnix,
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					// The JWT exp would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt iat after clock skew leeway",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"nbf": pastUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					// The JWT iat would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "valid jwt iat after clock skew leeway from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"nbf": pastUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					// The JWT iat would be invalid with clock skew leeway < 2 min
					ClockSkewLeeway: 2 * time.Minute,
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			v, err := NewValidator(keySet1, keySet2)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := v.Validate(ctx, token, tt.args.expected)

			// Expect to get back the same claims that were serialized in the JWT
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.args.claims, got)
		})
	}
}

func TestValidator_MultipleKeySets_NoExpIatNbf(t *testing.T) {
	tp := oidc.StartTestProvider(t, oidc.WithTestPort(8181))
	tp2 := oidc.StartTestProvider(t, oidc.WithTestPort(8182))

	// Create the KeySet to be used to verify JWT signatures
	keySet1, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	keySet2, err := NewOIDCDiscoveryKeySet(context.Background(), tp2.Addr(), tp2.CACert())
	require.NoError(t, err)

	testKeyID2 := fmt.Sprintf("%s-2", testKeyID)
	tp2.SetSigningKeys(priv, priv2.Public(), oidc.RS256, testKeyID2)

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "valid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
		{
			name: "valid jwt with assertion on issuer claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Issuer: "https://example.com/",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			v, err := NewValidator(keySet1, keySet2)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := v.ValidateAllowMissingIatNbfExp(ctx, token, tt.args.expected)

			// Expect to get back the same claims that were serialized in the JWT
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.args.claims, got)
		})
	}
}

// TestValidator_MultipleKeySets_Validate_Invalid_JWT tests cases where a JWT is expected to be invalid where the
// validator is initialized with multiple KeySets.
func TestValidator_MultipleKeySets_Validate_Invalid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t, oidc.WithTestPort(8181))
	tp2 := oidc.StartTestProvider(t, oidc.WithTestPort(8182))

	// Create the KeySet to be used to verify JWT signatures
	keySet1, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)

	keySet2, err := NewOIDCDiscoveryKeySet(context.Background(), tp2.Addr(), tp2.CACert())
	require.NoError(t, err)

	testKeyID2 := fmt.Sprintf("%s-2", testKeyID)
	tp2.SetSigningKeys(priv, priv2.Public(), oidc.RS256, testKeyID2)

	// Establish past, now, and future for validation of time related claims
	now := time.Now()
	nowUnix := float64(now.Unix())
	pastUnix := float64(now.Add(-2 * jwt.DefaultLeeway).Unix())
	futureUnix := float64(now.Add(2 * jwt.DefaultLeeway).Unix())

	type args struct {
		claims   map[string]interface{}
		token    func(map[string]interface{}) string
		expected Expected
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "invalid jwt with assertion on issuer claim",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Issuer: "https://wrong.com/",
				},
			},
		},
		{
			name: "invalid jwt with assertion on issuer claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Issuer: "https://wrong.com/",
				},
			},
		},
		{
			name: "invalid jwt with assertion on subject claim",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Subject: "bob@example.com",
				},
			},
		},
		{
			name: "invalid jwt with assertion on subject claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"sub": "alice@example.com",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Subject: "bob@example.com",
				},
			},
		},
		{
			name: "invalid jwt with assertion on id claim",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					ID: "123abc",
				},
			},
		},
		{
			name: "invalid jwt with assertion on id claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"jti": "abc123",
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					ID: "123abc",
				},
			},
		},
		{
			name: "invalid jwt with assertion on audience claim",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Audiences: []string{"www.example.com"},
				},
			},
		},
		{
			name: "invalid jwt with assertion on audience claim from key set 2",
			args: args{
				claims: map[string]interface{}{
					"aud": []interface{}{"www.other.com"},
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Audiences: []string{"www.example.com"},
				},
			},
		},
		{
			name: "invalid jwt with assertion on algorithm header parameter",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{ES256},
				},
			},
		},
		{
			name: "invalid jwt with assertion on algorithm header parameter from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{ES256},
				},
			},
		},
		{
			name: "invalid jwt from failed signature verification",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					// Sign the JWT with a key not in the test provider
					pk, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					return oidc.TestSignJWT(t, pk, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "invalid jwt from failed signature verification from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iat": nowUnix,
					"exp": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					// Sign the JWT with a key not in the test provider
					pk, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					return oidc.TestSignJWT(t, pk, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					SigningAlgorithms: []Alg{RS256},
				},
			},
		},
		{
			name: "invalid jwt with missing iat, nbf, and exp claims",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{},
			},
		},
		{
			name: "invalid jwt with missing iat, nbf, and exp claims from key set 2",
			args: args{
				claims: map[string]interface{}{
					"iss": "https://example.com/",
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{},
			},
		},
		{
			name: "invalid jwt with now before nbf",
			args: args{
				claims: map[string]interface{}{
					"nbf": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now before nbf from key set 2",
			args: args{
				claims: map[string]interface{}{
					"nbf": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(pastUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now after exp",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now after exp from key set 2",
			args: args{
				claims: map[string]interface{}{
					"exp": nowUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(futureUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now before iat",
			args: args{
				claims: map[string]interface{}{
					"nbf": pastUnix,
					"iat": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv, string(RS256), claims, []byte(testKeyID))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(nowUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid jwt with now before iat from key set 2",
			args: args{
				claims: map[string]interface{}{
					"nbf": pastUnix,
					"iat": futureUnix,
				},
				token: func(claims map[string]interface{}) string {
					return oidc.TestSignJWT(t, priv2, string(RS256), claims, []byte(testKeyID2))
				},
				expected: Expected{
					Now: func() time.Time {
						return time.Unix(int64(nowUnix), 0)
					},
				},
			},
		},
		{
			name: "invalid malformed jwt",
			args: args{
				token: func(claims map[string]interface{}) string {
					return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the signed JWT with the given claims
			token := tt.args.token(tt.args.claims)

			// Create the validator with the KeySet
			v, err := NewValidator(keySet1, keySet2)
			require.NoError(t, err)

			// Validate the JWT claims against expected values
			got, err := v.Validate(ctx, token, tt.args.expected)

			// Expect an error and nil claims
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}

func Test_validateAudience(t *testing.T) {
	type args struct {
		expectedAudiences []string
		audClaim          []string
		featureFlags      map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "skip validation for empty audiences",
			args: args{
				expectedAudiences: []string{},
				audClaim:          []string{"aud1"},
			},
		},
		{
			name: "at least one valid audience",
			args: args{
				expectedAudiences: []string{"aud11", "aud1", "aud12", "aud13"},
				audClaim:          []string{"aud0", "aud100", "aud1"},
			},
		},
		{
			name: "no valid audience",
			args: args{
				expectedAudiences: []string{"aud11", "aud15", "aud12", "aud13"},
				audClaim:          []string{"aud0", "aud100", "aud13"},
			},
		},
		{
			name: "normalized bound audience with trailing slash matches aud claim",
			args: args{
				expectedAudiences: []string{"aud11/", "aud13"},
				audClaim:          []string{"aud11", "aud0", "aud100"},
			},
		},
		{
			name: "normalized bound audience without trailing slash matches aud claim",
			args: args{
				expectedAudiences: []string{"aud11", "aud13"},
				audClaim:          []string{"aud11", "aud0", "aud100"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAudience(tt.args.expectedAudiences, tt.args.audClaim)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_validateSigningAlgorithm(t *testing.T) {
	type args struct {
		token              func() string
		expectedAlgorithms []Alg
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default of RS256 when expected algorithms is empty",
			args: args{
				token: func() string {
					return oidc.TestSignJWT(t, priv, string(RS256), testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{},
			},
		},
		{
			name: "jwt signed with at least one expected signing algorithm",
			args: args{
				token: func() string {
					return oidc.TestSignJWT(t, priv, string(PS384), testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{RS256, EdDSA, RS512, PS384, PS256},
			},
		},
		{
			name: "jwt signed with unexpected algorithm",
			args: args{
				token: func() string {
					return oidc.TestSignJWT(t, priv, string(RS256), testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{RS512, PS384, ES256},
			},
			wantErr: true,
		},
		{
			name: "unsupported signing algorithm",
			args: args{
				token: func() string {
					return oidc.TestSignJWT(t, priv, string(RS256), testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{Alg("none")},
			},
			wantErr: true,
		},
		{
			name: "jwt missing signature",
			args: args{
				token: func() string {
					token := oidc.TestSignJWT(t, priv, string(RS256), testJWTClaims(t), []byte(testKeyID))
					parts := strings.Split(token, ".")
					require.Equal(t, 3, len(parts))
					parts[2] = "" // strip the signature
					return strings.Join(parts, ".")
				},
				expectedAlgorithms: []Alg{RS512},
			},
			wantErr: true,
		},
		{
			name: "malformed jwt",
			args: args{
				token: func() string {
					return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
				},
				expectedAlgorithms: []Alg{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSigningAlgorithm(tt.args.token(), tt.args.expectedAlgorithms)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
