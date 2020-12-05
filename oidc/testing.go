package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestGenerateKeys will generate a test ECDSA P-256 pub/priv key pair
func TestGenerateKeys(t *testing.T) (pub, priv string) {
	t.Helper()
	require := require.New(t)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(err)

	{
		derBytes, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(err)

		pemBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		}
		priv = string(pem.EncodeToMemory(pemBlock))
	}
	{
		derBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
		require.NoError(err)

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		}
		pub = string(pem.EncodeToMemory(pemBlock))
	}

	return pub, priv
}

// TestSignJWT will bundle the provided claims into a test signed JWT. The provided key
// must be ECDSA.
func TestSignJWT(t *testing.T, ecdsaPrivKeyPEM string, claims jwt.Claims, privateClaims interface{}) string {
	t.Helper()
	require := require.New(t)
	var key *ecdsa.PrivateKey
	block, _ := pem.Decode([]byte(ecdsaPrivKeyPEM))
	if block != nil {
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		require.NoError(err)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(err)

	raw, err := jwt.Signed(sig).
		Claims(claims).
		Claims(privateClaims).
		CompactSerialize()
	require.NoError(err)

	return raw
}

// testDefaultJwt is internally helpful, but for now we won't export it.
func testDefaultJwt(t *testing.T, ecdsaPrivKeyPEM string, expireIn time.Duration, nonce string, additionalClaims map[string]interface{}) string {
	t.Helper()
	now := jwt.NewNumericDate(time.Now())
	claims := jwt.Claims{
		Issuer:    "https://example.com/",
		IssuedAt:  now,
		NotBefore: now,
		Expiry:    jwt.NewNumericDate(time.Now()),
		Audience:  []string{"www.example.com"},
		Subject:   "alice@example.com",
	}
	privateClaims := map[string]interface{}{
		nonce: nonce,
	}
	for k, v := range additionalClaims {
		privateClaims[k] = v
	}
	testJwt := TestSignJWT(t, ecdsaPrivKeyPEM, claims, privateClaims)
	return testJwt
}
