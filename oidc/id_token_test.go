package oidc

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
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
	testIat := jwt.NewNumericDate(time.Now())
	testExp := jwt.NewNumericDate(time.Now().Add(10 * time.Minute))

	claims := jwt.Claims{
		Issuer:   "https://example.com/",
		IssuedAt: testIat,
		Expiry:   testExp,
		Audience: []string{"www.example.com"},
		Subject:  "alice@example.com",
	}
	testJWT := TestSignJWT(t, priv, claims, map[string]interface{}{})
	t.Parallel()
	t.Run("all-claim", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tk := IDToken(testJWT)
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
