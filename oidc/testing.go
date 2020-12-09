package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/bmizerany/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestGenerateKeys will generate a test ECDSA P-256 pub/priv key pair
func TestGenerateKeys(t *testing.T) (crypto.PublicKey, crypto.PrivateKey) {
	t.Helper()
	require := require.New(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(err)
	return priv.PublicKey, priv
}

// TestSignJWT will bundle the provided claims into a test signed JWT. The provided key
// must be ECDSA.
func TestSignJWT(t *testing.T, key crypto.PrivateKey, alg Alg, claims jwt.Claims, privateClaims interface{}) string {
	t.Helper()
	require := require.New(t)

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: key},
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

func testHashAccessToken(t *testing.T, idSigTokenAlg Alg, token AccessToken) string {
	t.Helper()
	require := require.New(t)
	var h hash.Hash
	switch idSigTokenAlg {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512:
		h = sha512.New()
	default:
		require.FailNowf("testHashAccessToken: unsupported signing algorithm %q: %w", string(idSigTokenAlg))
	}
	require.NotNil(h)
	_, _ = h.Write([]byte(string(token))) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	return actual
}

// testDefaultJwt is internally helpful, but for now we won't export it.
func testDefaultJwt(t *testing.T, privKey crypto.PrivateKey, expireIn time.Duration, nonce string, additionalClaims map[string]interface{}) string {
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
	testJwt := TestSignJWT(t, privKey, ES256, claims, privateClaims)
	return testJwt
}

// testNewConfig creates a new config from the TestProvider.  The TestProvider
// must have already set it's client id and secret via
// tp.SetClientCreds("TEST-CLIENT-ID", "TEST-CLIENT-SECRET")
// This is helpful internally, but intentionally not exported.
func testNewConfig(t *testing.T, clientId, clientSecret, redirectUrl string, tp *TestProvider) *Config {
	const op = "testNewConfig"
	t.Helper()
	require := require.New(t)

	require.NotEmptyf(clientId, "%s: client id is empty", op)
	require.NotEmptyf(clientSecret, "%s: client secret is empty", op)
	require.NotEmptyf(redirectUrl, "%s: redirect URL is empty", op)

	tp.SetClientCreds(clientId, clientSecret)

	c, err := NewConfig(
		tp.Addr(),
		clientId,
		ClientSecret(clientSecret),
		[]Alg{tp.SigningAlgorithm()},
		redirectUrl,
		WithProviderCA(tp.CACert()),
	)
	require.NoError(err)
	return c
}

func testNewProvider(t *testing.T, clientId, clientSecret, redirectUrl string, tp *TestProvider) *Provider {
	const op = "testNewProvider"
	t.Helper()
	require := require.New(t)
	require.NotEmptyf(clientId, "%s: client id is empty", op)
	require.NotEmptyf(clientSecret, "%s: client secret is empty", op)
	require.NotEmptyf(redirectUrl, "%s: redirect URL is empty", op)

	tc := testNewConfig(t, clientId, clientSecret, redirectUrl, tp)
	p, err := NewProvider(tc)
	require.NoError(err)
	return p
}

func testAssertEqualFunc(t *testing.T, wantFunc, gotFunc interface{}, format string, args ...interface{}) {
	t.Helper()
	want := runtime.FuncForPC(reflect.ValueOf(wantFunc).Pointer()).Name()
	got := runtime.FuncForPC(reflect.ValueOf(gotFunc).Pointer()).Name()
	assert.Equalf(t, want, got, format, args...)
}
