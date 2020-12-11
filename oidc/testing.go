package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"math/big"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestGenerateKeys will generate a test ECDSA P-256 pub/priv key pair.
func TestGenerateKeys(t *testing.T) (crypto.PublicKey, crypto.PrivateKey) {
	t.Helper()
	require := require.New(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(err)
	return priv.PublicKey, priv
}

// TestSignJWT will bundle the provided claims into a test signed JWT.
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
func testDefaultJWT(t *testing.T, privKey crypto.PrivateKey, expireIn time.Duration, nonce string, additionalClaims map[string]interface{}) string {
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

// testNewConfig creates a new config from the TestProvider.
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

// TestGenerateCA will generate a test x509 CA cert, along with it encoded in a
// PEM format.
func TestGenerateCA(t *testing.T, hosts []string) (*x509.Certificate, string) {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	validFor := 2 * time.Minute
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(err)

	c, err := x509.ParseCertificate(derBytes)
	require.NoError(err)

	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}
