package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// KeySet represents a set of keys that can be used to verify the signatures of JWTs.
// A KeySet is expected to be backed by a set of local or remote keys.
type KeySet interface {

	// VerifySignature parses the given JWT, verifies its signature, and returns the claims in its payload.
	VerifySignature(ctx context.Context, token string) (claims map[string]interface{}, err error)
}

// OIDCDiscoveryKeySet verifies JWT signatures using keys obtained by the OIDC discovery mechanism.
type OIDCDiscoveryKeySet struct {
	provider *oidc.Provider
}

// JSONWebKeySet verifies JWT signatures using keys obtained from a JWKS URL.
type JSONWebKeySet struct {
	remoteJWKS oidc.KeySet
}

// StaticKeySet verifies JWT signatures using local PEM-encoded public keys.
type StaticKeySet struct {
	publicKeys []interface{}
}

// NewOIDCDiscoveryKeySet returns a KeySet that verifies JWT signatures using keys from the
// JSON Web Key Set (JWKS) published in the discovery document at the given discoveryURL.
// The client used to obtain the remote keys will verify server certificates using the root
// certificates provided by discoveryCAPEM.
func NewOIDCDiscoveryKeySet(ctx context.Context, discoveryURL string, discoveryCAPEM string) (KeySet, error) {
	if discoveryURL == "" {
		return nil, errors.New("discoveryURL must not be empty")
	}

	caCtx, err := createCAContext(ctx, discoveryCAPEM)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(caCtx, discoveryURL)
	if err != nil {
		return nil, err
	}

	return &OIDCDiscoveryKeySet{
		provider: provider,
	}, nil
}

// VerifySignature parses the given JWT, verifies its signature using discovered JWKS keys, and
// returns the claims in its payload. The given JWT must be of the JWS compact serialization form.
func (ks OIDCDiscoveryKeySet) VerifySignature(ctx context.Context, token string) (map[string]interface{}, error) {
	// Verify only the signature
	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
		SkipIssuerCheck:   true,
	}

	verifier := ks.provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	allClaims := make(map[string]interface{})
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, err
	}

	return allClaims, nil
}

// NewJSONWebKeySet returns a KeySet that verifies JWT signatures using keys from the JSON Web
// Key Set (JWKS) at the given jwksURL. The client used to obtain the remote JWKS will verify
// server certificates using the root certificates provided by jwksCAPEM.
func NewJSONWebKeySet(ctx context.Context, jwksURL string, jwksCAPEM string) (KeySet, error) {
	if jwksURL == "" {
		return nil, errors.New("jwksURL must not be empty")
	}

	caCtx, err := createCAContext(ctx, jwksCAPEM)
	if err != nil {
		return nil, err
	}

	return JSONWebKeySet{
		remoteJWKS: oidc.NewRemoteKeySet(caCtx, jwksURL),
	}, nil
}

// VerifySignature parses the given JWT, verifies its signature using JWKS keys, and returns
// the claims in its payload. The given JWT must be of the JWS compact serialization form.
func (ks JSONWebKeySet) VerifySignature(ctx context.Context, token string) (map[string]interface{}, error) {
	payload, err := ks.remoteJWKS.VerifySignature(ctx, token)
	if err != nil {
		return nil, err
	}

	// Unmarshal payload into a set of all received claims
	allClaims := map[string]interface{}{}
	if err := json.Unmarshal(payload, &allClaims); err != nil {
		return nil, err
	}

	return allClaims, nil
}

// NewStaticKeySet returns a KeySet that verifies JWT signatures using PEM-encoded public keys.
// The given publicKeys must be of PEM-encoded x509 certificate or PKIX public key forms.
func NewStaticKeySet(publicKeys []string) (KeySet, error) {
	parsedPublicKeys := make([]interface{}, 0)
	for _, k := range publicKeys {
		key, err := parsePublicKeyPEM([]byte(k))
		if err != nil {
			return nil, err
		}
		parsedPublicKeys = append(parsedPublicKeys, key)
	}

	return StaticKeySet{
		publicKeys: parsedPublicKeys,
	}, nil
}

// VerifySignature parses the given JWT, verifies its signature using local PEM-encoded public keys,
// and returns the claims in its payload. The given JWT must be of the JWS compact serialization form.
func (ks StaticKeySet) VerifySignature(_ context.Context, token string) (map[string]interface{}, error) {
	parsedJWT, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	var valid bool
	allClaims := map[string]interface{}{}
	for _, key := range ks.publicKeys {
		if err := parsedJWT.Claims(key, &allClaims); err == nil {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errors.New("no known key successfully validated the token signature")
	}

	return allClaims, nil
}

// parsePublicKeyPEM is used to parse RSA and ECDSA public keys from PEMs.
// It returns a *rsa.PublicKey or *ecdsa.PublicKey.
func parsePublicKeyPEM(data []byte) (interface{}, error) {
	block, data := pem.Decode(data)
	if block != nil {
		var rawKey interface{}
		var err error
		if rawKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				rawKey = cert.PublicKey
			} else {
				return nil, err
			}
		}

		if rsaPublicKey, ok := rawKey.(*rsa.PublicKey); ok {
			return rsaPublicKey, nil
		}
		if ecPublicKey, ok := rawKey.(*ecdsa.PublicKey); ok {
			return ecPublicKey, nil
		}
	}

	return nil, errors.New("data does not contain any valid RSA or ECDSA public keys")
}

// createCAContext returns a context with a custom TLS client that's configured with the root
// certificates from caPEM. If no certificates are configured, the original context is returned.
func createCAContext(ctx context.Context, caPEM string) (context.Context, error) {
	if caPEM == "" {
		return ctx, nil
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(caPEM)); !ok {
		return nil, errors.New("could not parse CA PEM value successfully")
	}

	tr := cleanhttp.DefaultPooledTransport()
	if certPool != nil {
		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	tc := &http.Client{
		Transport: tr,
	}

	caCtx := context.WithValue(ctx, oauth2.HTTPClient, tc)

	return caCtx, nil
}
