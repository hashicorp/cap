package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestValidator_Validate_Valid_JWT tests cases where a JWT is expected to be valid.
func TestValidator_Validate_Valid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	// Create the KeySet to be used to verify JWT signatures
	keySet, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	// Generate a key to sign JWTs with throughout most test cases
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS512, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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

// TestValidator_Validate_Valid_JWT tests cases where a JWT is expected to be invalid.
func TestValidator_Validate_Invalid_JWT(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	// Create the KeySet to be used to verify JWT signatures
	keySet, err := NewOIDCDiscoveryKeySet(context.Background(), tp.Addr(), tp.CACert())
	require.NoError(t, err)

	// Generate a key to sign JWTs with throughout most test cases
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					pk, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					return testSignJWT(t, pk, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
					return testSignJWT(t, priv, RS256, claims, []byte(testKeyID))
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
		keySet func() KeySet
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "new validator with keySet",
			args: args{
				keySet: func() KeySet {
					ks, err := NewJSONWebKeySet(context.Background(),
						"https://issuer.com/"+wellKnownJWKS, "")
					require.NoError(t, err)
					return ks
				},
			},
		},
		{
			name: "new validator with nil keySet",
			args: args{
				keySet: func() KeySet {
					return nil
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewValidator(tt.args.keySet())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func Test_validateAudience(t *testing.T) {
	type args struct {
		expectedAudiences []string
		audClaim          []string
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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
					return testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{},
			},
		},
		{
			name: "jwt signed with at least one expected signing algorithm",
			args: args{
				token: func() string {
					return testSignJWT(t, priv, PS384, testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{RS256, EdDSA, RS512, PS384, PS256},
			},
		},
		{
			name: "jwt signed with unexpected algorithm",
			args: args{
				token: func() string {
					return testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{RS512, PS384, ES256},
			},
			wantErr: true,
		},
		{
			name: "unsupported signing algorithm",
			args: args{
				token: func() string {
					return testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
				},
				expectedAlgorithms: []Alg{Alg("none")},
			},
			wantErr: true,
		},
		{
			name: "jwt missing signature",
			args: args{
				token: func() string {
					token := testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
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
