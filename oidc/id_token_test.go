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
)

func TestIDToken_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = RedactedIDToken
		tk := IDToken("super secret token")
		assert.Equalf(want, tk.String(), "IDToken.String() = %v, want %v", tk.String(), want)
	})
}

func TestIDToken_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, RedactedIDToken)
		tk := IDToken("super secret token")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "IDToken.MarshalJSON() = %s, want %s", got, want)
	})
}

type testSubClaims struct {
	Sub string
}

func TestIDToken_Claims(t *testing.T) {
	_, priv := TestGenerateKeys(t)
	testIat := float64(time.Now().Unix())
	testExp := float64(time.Now().Add(10 * time.Minute).Unix())

	claims := map[string]interface{}{
		"iss": "https://example.com/",
		"iat": testIat,
		"exp": testExp,
		"aud": []string{"www.example.com"},
		"sub": "alice@example.com",
	}
	testJWT := TestSignJWT(t, priv, ES256, claims, nil)
	t.Parallel()
	t.Run("all-claim", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IDToken(testJWT)
		var claims map[string]interface{}
		err := tk.Claims(&claims)
		require.NoError(err)
		assert.Equal(map[string]interface{}{
			"iat": testIat,
			"exp": testExp,
			"iss": "https://example.com/",
			"sub": "alice@example.com",
			"aud": []interface{}{"www.example.com"},
		}, claims)
	})
	t.Run("only-sub-claim", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IDToken(testJWT)
		var subOnly testSubClaims
		err := tk.Claims(&subOnly)
		require.NoError(err)
		assert.Equal(testSubClaims{Sub: "alice@example.com"}, subOnly)
	})
	t.Run("no-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IDToken("")
		var claims map[string]interface{}
		err := tk.Claims(&claims)
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidParameter), "wanted \"%s\" but got \"%s\"", ErrInvalidParameter, err)
	})
	t.Run("nil-claims", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IDToken(testJWT)
		err := tk.Claims(nil)
		require.Error(err)
		assert.Truef(errors.Is(err, ErrNilParameter), "wanted \"%s\" but got \"%s\"", ErrNilParameter, err)
	})
}

func TestIDToken_VerifyAccessToken(t *testing.T) {
	t.Parallel()
	testIat := float64(time.Now().Unix())
	testExp := float64(time.Now().Add(10 * time.Minute).Unix())
	claims := map[string]interface{}{
		"iss": "https://example.com/",
		"iat": testIat,
		"exp": testExp,
		"aud": []string{"www.example.com"},
		"sub": "alice@example.com",
	}
	tests := []struct {
		name        string
		t           IDToken
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
			claims["at_hash"] = testHashAccessToken(t, tt.alg, tt.accessToken)
			testJWT := TestSignJWT(t, tt.priKey, tt.alg, claims, nil)
			tk := IDToken(testJWT)
			err := tk.VerifyAccessToken(tt.accessToken)
			require.NoError(err)
		})
	}
}
