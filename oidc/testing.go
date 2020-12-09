package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
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

// testDefaultJWT is internally helpful, but for now we won't export it.
func testDefaultJWT(t *testing.T, ecdsaPrivKeyPEM string, expireIn time.Duration, nonce string, additionalClaims map[string]interface{}) string {
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
	testJWT := TestSignJWT(t, ecdsaPrivKeyPEM, claims, privateClaims)
	return testJWT
}

// TestGenerateCA will generate a test x509 CA cert encoded in a PEM format.
func TestGenerateCA(t *testing.T, hosts []string) string {
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

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}
