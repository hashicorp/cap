package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	wellKnownJWKS = "/.well-known/jwks.json"
	testKeyID     = "test-key"
)

func Test_jsonWebKeySet_VerifySignature(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	type args struct {
		token func() string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name: "verify jwt with ES256 signature",
			args: args{
				token: func() string {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.ES256, testKeyID)
					return testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with ES384 signature",
			args: args{
				token: func() string {
					priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.ES384, testKeyID)
					return testSignJWT(t, priv, ES384, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with ES512 signature",
			args: args{
				token: func() string {
					priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.ES512, testKeyID)
					return testSignJWT(t, priv, ES512, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS256 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.RS256, testKeyID)
					return testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS384 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 3072)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.RS384, testKeyID)
					return testSignJWT(t, priv, RS384, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS512 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.RS512, testKeyID)
					return testSignJWT(t, priv, RS512, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS256 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.PS256, testKeyID)
					return testSignJWT(t, priv, PS256, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS384 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 3072)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.PS384, testKeyID)
					return testSignJWT(t, priv, PS384, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS512 signature",
			args: args{
				token: func() string {
					priv, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.PS512, testKeyID)
					return testSignJWT(t, priv, PS512, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with EdDSA signature",
			args: args{
				token: func() string {
					pub, priv, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, pub, oidc.EdDSA, testKeyID)
					return testSignJWT(t, priv, EdDSA, testJWTClaims(t), []byte(testKeyID))
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "fail to verify jwt signature with unrelated public and private key pairs",
			args: args{
				token: func() string {
					// Intentionally not setting signing keys on the testing provider so that
					// the default public key in the JWKS is not mathematically related to the
					// private key that's used to sign the token.

					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					return testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify jwt signature after modifying header",
			args: args{
				token: func() string {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.ES256, testKeyID)

					// Replace the header with information that would change the signature
					token := testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
					parts := strings.Split(token, ".")
					require.Equal(t, 3, len(parts))
					parts[0] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
					return strings.Join(parts, ".")
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify jwt signature after modifying payload",
			args: args{
				token: func() string {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					tp.SetSigningKeys(priv, priv.Public(), oidc.ES256, testKeyID)

					// Replace the payload with information that would change the signature
					token := testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
					parts := strings.Split(token, ".")
					require.Equal(t, 3, len(parts))
					parts[1] = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
					return strings.Join(parts, ".")
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify signature of malformed jwt",
			args: args{
				token: func() string {
					return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
				},
			},
			wantErr: true,
		},
		{
			name: "fail to parse malformed JWKS response",
			args: args{
				token: func() string {
					// Return a malformed JWKS response from the test provider
					tp.SetInvalidJWKS(true)

					priv, _, alg, id := tp.SigningKeys()
					return testSignJWT(t, priv, Alg(alg), testJWTClaims(t), []byte(id))
				},
			},
			wantErr: true,
		},
		{
			name: "fail request for keys from JWKS URL with 404",
			args: args{
				token: func() string {
					// Disable the JWKS URL so that fetching the keys from the test provider fails
					tp.SetDisableJWKs(true)

					priv, _, alg, id := tp.SigningKeys()
					return testSignJWT(t, priv, Alg(alg), testJWTClaims(t), []byte(id))
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create the KeySet with the JWKS URL
			keySet, err := NewJSONWebKeySet(ctx, tp.Addr()+wellKnownJWKS, tp.CACert())
			require.NoError(t, err)
			require.NotNil(t, keySet)

			// Verify the token signature
			got, err := keySet.VerifySignature(ctx, tt.args.token())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_staticKeySet_VerifySignature(t *testing.T) {
	type args struct {
		token func() (string, []crypto.PublicKey)
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name: "verify jwt with ES256 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					token := testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with ES384 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					token := testSignJWT(t, priv, ES384, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with ES512 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					require.NoError(t, err)
					token := testSignJWT(t, priv, ES512, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS256 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					token := testSignJWT(t, priv, RS256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS384 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 3072)
					require.NoError(t, err)
					token := testSignJWT(t, priv, RS384, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with RS512 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					token := testSignJWT(t, priv, RS512, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS256 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					token := testSignJWT(t, priv, PS256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS384 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 3072)
					require.NoError(t, err)
					token := testSignJWT(t, priv, PS384, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with PS512 signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 4096)
					require.NoError(t, err)
					token := testSignJWT(t, priv, PS512, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt with EdDSA signature",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					pub, priv, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)
					token := testSignJWT(t, priv, EdDSA, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{pub}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "verify jwt signature with many public keys of different types provided",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					edPub, _, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)
					ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)

					token := testSignJWT(t, rsaPriv, RS256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{edPub, ecPriv.Public(), rsaPriv.Public()}
				},
			},
			want: testJWTClaims(t),
		},
		{
			name: "fail to verify jwt signature with many unrelated public and private key pairs",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					edPub, _, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)
					ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)

					token := testSignJWT(t, ecPriv, ES256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{edPub, rsaPriv.Public()}
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify jwt signature with unrelated public and private key pairs",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					token := testSignJWT(t, priv1, ES256, testJWTClaims(t), []byte(testKeyID))
					return token, []crypto.PublicKey{priv2.Public()}
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify jwt signature after modifying header",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					// Replace the header with information that would change the signature
					token := testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
					parts := strings.Split(token, ".")
					require.Equal(t, 3, len(parts))
					parts[0] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
					return strings.Join(parts, "."), []crypto.PublicKey{priv.Public()}
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify jwt signature after modifying payload",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					// Replace the payload with information that would change the signature
					token := testSignJWT(t, priv, ES256, testJWTClaims(t), []byte(testKeyID))
					parts := strings.Split(token, ".")
					require.Equal(t, 3, len(parts))
					parts[1] = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
					return strings.Join(parts, "."), []crypto.PublicKey{priv.Public()}
				},
			},
			wantErr: true,
		},
		{
			name: "fail to verify signature of malformed jwt",
			args: args{
				token: func() (string, []crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", []crypto.PublicKey{priv.Public()}
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, pubKeys := tt.args.token()

			// Create the KeySet with the public keys
			keySet, err := NewStaticKeySet(pubKeys)
			require.NoError(t, err)
			require.NotNil(t, keySet)

			// Verify the token signature
			got, err := keySet.VerifySignature(context.Background(), token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNewJSONWebKeySet(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	type args struct {
		jwksURL   string
		jwksCAPEM string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid JWKS URL",
			args: args{
				jwksURL:   tp.Addr() + wellKnownJWKS,
				jwksCAPEM: "",
			},
		},
		{
			name: "valid JWKS URL and CA PEM",
			args: args{
				jwksURL:   tp.Addr() + wellKnownJWKS,
				jwksCAPEM: tp.CACert(),
			},
		},
		{
			name: "empty JWKS URL",
			args: args{
				jwksURL: "",
			},
			wantErr: true,
		},
		{
			name: "malformed JWKS CA PEM",
			args: args{
				jwksURL:   tp.Addr() + wellKnownJWKS,
				jwksCAPEM: "-----BEGIN CERTIFICATE-----",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONWebKeySet(context.Background(), tt.args.jwksURL, tt.args.jwksCAPEM)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewOIDCDiscoveryKeySet(t *testing.T) {
	tp := oidc.StartTestProvider(t)

	type args struct {
		issuer             string
		issuerCAPEM        string
		modifyTestProvider func()
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid issuer and CA PEM",
			args: args{
				issuer:      tp.Addr(),
				issuerCAPEM: tp.CACert(),
			},
		},
		{
			name: "empty issuer URL",
			args: args{
				issuer: "",
			},
			wantErr: true,
		},
		{
			name: "invalid issuer URL",
			args: args{
				issuer: "https:example.com/",
			},
			wantErr: true,
		},
		{
			name: "malformed issuer CA PEM",
			args: args{
				issuer:      tp.Addr(),
				issuerCAPEM: "-----BEGIN CERTIFICATE-----",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOIDCDiscoveryKeySet(context.Background(), tt.args.issuer, tt.args.issuerCAPEM)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewStaticKeySet(t *testing.T) {
	type args struct {
		publicKeys func() []crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid public keys",
			args: args{
				publicKeys: func() []crypto.PublicKey {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					return []crypto.PublicKey{priv.Public()}
				},
			},
		},
		{
			name: "empty public keys",
			args: args{
				publicKeys: func() []crypto.PublicKey {
					return nil
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStaticKeySet(tt.args.publicKeys())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func testJWTClaims(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"iss": "https://example.com/",
		"sub": "alice@example.com",
		"aud": []interface{}{"www.example.com"},
		"exp": float64(1611699944),
		"nbf": float64(1611699344),
		"iat": float64(1611699344),
		"jti": "abc123",
	}
}

func testSignJWT(t *testing.T, key crypto.PrivateKey, alg Alg, claims interface{}, keyID []byte) string {
	t.Helper()

	hdr := map[jose.HeaderKey]interface{}{}
	if keyID != nil {
		hdr["key_id"] = string(keyID)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: key},
		(&jose.SignerOptions{ExtraHeaders: hdr}).WithType("JWT"),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(sig).
		Claims(claims).
		CompactSerialize()
	require.NoError(t, err)
	return raw
}

func TestParsePublicKeyPEM(t *testing.T) {
	type args struct {
		pem func() ([]byte, crypto.PublicKey)
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "parse PKIX RSA public key",
			args: args{
				pem: func() ([]byte, crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)

					bytes, err := x509.MarshalPKIXPublicKey(priv.Public())
					require.NoError(t, err)
					return pem.EncodeToMemory(&pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: bytes,
					}), priv.Public()
				},
			},
		},
		{
			name: "parse PKIX ECDSA public key",
			args: args{
				pem: func() ([]byte, crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					bytes, err := x509.MarshalPKIXPublicKey(priv.Public())
					require.NoError(t, err)
					return pem.EncodeToMemory(&pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: bytes,
					}), priv.Public()
				},
			},
		},
		{
			name: "parse x509 certificate RSA public key",
			args: args{
				pem: func() ([]byte, crypto.PublicKey) {
					priv, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)

					template := x509.Certificate{
						SerialNumber: new(big.Int).SetInt64(123),
					}
					cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
					require.NoError(t, err)
					return pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert,
					}), priv.Public()
				},
			},
		},
		{
			name: "parse x509 certificate ECDSA public key",
			args: args{
				pem: func() ([]byte, crypto.PublicKey) {
					priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					template := x509.Certificate{
						SerialNumber: new(big.Int).SetInt64(123),
					}
					cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
					require.NoError(t, err)
					return pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert,
					}), priv.Public()
				},
			},
		},
		{
			name: "malformed PEM",
			args: args{
				pem: func() ([]byte, crypto.PublicKey) {
					return []byte(`"-----BEGIN CERTIFICATE-----"`), nil
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemBytes, pub := tt.args.pem()
			got, err := ParsePublicKeyPEM(pemBytes)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, pub, got)
		})
	}
}

func Test_unmarshalResp(t *testing.T) {
	type args struct {
		r    *http.Response
		body []byte
		v    interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid JSON response",
			args: args{
				body: []byte(`{"valid":"json"}`),
				v: struct {
					valid string `json:"valid"`
				}{},
				r: &http.Response{},
			},
		},
		{
			name: "invalid JSON response with no content-type header",
			args: args{
				body: []byte(`{"invalid":"j}`),
				v: struct {
					invalid string `json:"invalid"`
				}{},
				r: &http.Response{},
			},
			wantErr: true,
		},
		{
			name: "invalid JSON response with application/json content-type header",
			args: args{
				body: []byte(`{"invalid":"j}`),
				v: struct {
					invalid string `json:"invalid"`
				}{},
				r: &http.Response{
					Header: map[string][]string{
						"Content-Type": {"application/json"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid JSON response with text/html content-type header",
			args: args{
				body: []byte(`{"invalid":"j}`),
				v: struct {
					invalid string `json:"invalid"`
				}{},
				r: &http.Response{
					Header: map[string][]string{
						"Content-Type": {"text/html"},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unmarshalResp(tt.args.r, tt.args.body, tt.args.v)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
