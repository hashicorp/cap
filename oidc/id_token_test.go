package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestIdToken_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = RedactedIdToken
		tk := IdToken("super secret token")
		assert.Equalf(want, tk.String(), "IdToken.String() = %v, want %v", tk.String(), want)
	})
}

func TestIdToken_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, RedactedIdToken)
		tk := IdToken("super secret token")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "IdToken.MarshalJSON() = %s, want %s", got, want)
	})
}

type testSubClaims struct {
	Sub string
}

func TestIdToken_Claims(t *testing.T) {
	_, priv := TestGenerateKeys(t)
	testIat := jwt.NewNumericDate(time.Now())
	testExp := jwt.NewNumericDate(time.Now().Add(10 * time.Minute))

	claims := jwt.Claims{
		Issuer:   "https://example.com/",
		IssuedAt: testIat,
		Expiry:   testExp,
		Audience: []string{"www.example.com"},
		Subject:  "alice@example.com",
	}
	testJwt := TestSignJWT(t, priv, ES256, claims, map[string]interface{}{})
	t.Parallel()
	t.Run("all-claim", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IdToken(testJwt)
		var claims map[string]interface{}
		err := tk.Claims(&claims)
		require.NoError(err)
		assert.Equal(map[string]interface{}{
			"iat": float64(testIat.Time().Unix()),
			"exp": float64(testExp.Time().Unix()),
			"iss": "https://example.com/",
			"sub": "alice@example.com",
			"aud": []interface{}{"www.example.com"},
		}, claims)
	})
	t.Run("only-sub-claim", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IdToken(testJwt)
		var subOnly testSubClaims
		err := tk.Claims(&subOnly)
		require.NoError(err)
		assert.Equal(testSubClaims{Sub: "alice@example.com"}, subOnly)
	})
	t.Run("no-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IdToken("")
		var claims map[string]interface{}
		err := tk.Claims(&claims)
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidParameter), "wanted \"%s\" but got \"%s\"", ErrInvalidParameter, err)
	})
	t.Run("nil-claims", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IdToken(testJwt)
		err := tk.Claims(nil)
		require.Error(err)
		assert.Truef(errors.Is(err, ErrNilParameter), "wanted \"%s\" but got \"%s\"", ErrNilParameter, err)
	})
}

func TestIdToken_VerifyAccessToken(t *testing.T) {
	t.Parallel()
	testIat := jwt.NewNumericDate(time.Now())
	testExp := jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	stdClaims := jwt.Claims{
		Issuer:   "https://example.com/",
		IssuedAt: testIat,
		Expiry:   testExp,
		Audience: []string{"www.example.com"},
		Subject:  "alice@example.com",
	}
	tests := []struct {
		name        string
		t           IdToken
		priKey      crypto.PrivateKey
		alg         Alg
		accessToken AccessToken
		wantErr     bool
		wantIsErr   error
	}{
		{
			name: "RS256",
			alg:  RS256,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "ES256",
			alg:  ES256,
			priKey: func() crypto.PrivateKey {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "PS256",
			alg:  PS256,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "RS384",
			alg:  RS384,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "ES384",
			alg:  ES384,
			priKey: func() crypto.PrivateKey {
				k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "PS384",
			alg:  PS384,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "RS512",
			alg:  RS512,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "ES512",
			alg:  ES512,
			priKey: func() crypto.PrivateKey {
				k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
		{
			name: "PS512",
			alg:  PS512,
			priKey: func() crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return k
			}(),
			accessToken: "test-access-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			additionalClaims := map[string]interface{}{
				"at_hash": testHashAccessToken(t, tt.alg, tt.accessToken),
			}
			testJWT := TestSignJWT(t, tt.priKey, tt.alg, stdClaims, additionalClaims)
			tk := IdToken(testJWT)
			err := tk.VerifyAccessToken(tt.accessToken)
			require.NoError(err)
		})
	}
}
