package oidc

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc/internal/strutils"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestProvider is local server that supports test provider capabilities which
// make writing tests much easier.  Most of this is from Consul's oauthtest
// package with a few changes so it could become part of this package's public
// testing API.  A big thanks to the original contributors to Consul's oauthtest
// package.
type TestProvider struct {
	httpServer *httptest.Server
	caCert     string

	jwks                *jose.JSONWebKeySet
	allowedRedirectURIs []string
	replySubject        string
	replyUserinfo       map[string]interface{}

	mu                sync.Mutex
	clientID          string
	clientSecret      string
	expectedAuthCode  string
	expectedAuthNonce string
	customClaims      map[string]interface{}
	customAudience    string
	omitIDToken       bool
	disableUserInfo   bool

	ecdsaPublicKey  string
	ecdsaPrivateKey string

	t *testing.T
}

// Stop stops the running TestProvider.
func (p *TestProvider) Stop() {
	p.httpServer.Close()
}

// StartTestProvider creates a disposable TestProvider.  The port must not be
// zero.
func StartTestProvider(t *testing.T, port int) *TestProvider {
	t.Helper()
	require := require.New(t)

	p := &TestProvider{
		allowedRedirectURIs: []string{
			"https://example.com",
		},
		replySubject: "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
		replyUserinfo: map[string]interface{}{
			"color":       "red",
			"temperature": "76",
			"flavor":      "umami",
		},
	}
	p.ecdsaPublicKey, p.ecdsaPrivateKey = TestGenerateKeys(t)

	p.jwks = testJWKS(t, p.ecdsaPublicKey)

	p.httpServer = httptestNewUnstartedServerWithPort(t, p, port)
	p.httpServer.Config.ErrorLog = log.New(ioutil.Discard, "", 0)
	p.httpServer.StartTLS()
	t.Cleanup(p.httpServer.Close)

	cert := p.httpServer.Certificate()

	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(err)
	p.caCert = buf.String()

	return p
}

// SetClientCreds is for configuring the client information required for the
// OIDC workflows.
func (p *TestProvider) SetClientCreds(clientID, clientSecret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clientID = clientID
	p.clientSecret = clientSecret
}

// SetExpectedAuthCode configures the auth code to return from /auth and the
// allowed auth code for /token.
func (p *TestProvider) SetExpectedAuthCode(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedAuthCode = code
}

// SetExpectedAuthNonce configures the nonce value required for /auth.
func (p *TestProvider) SetExpectedAuthNonce(nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedAuthNonce = nonce
}

// SetAllowedRedirectURIs allows you to configure the allowed redirect URIs for
// the OIDC workflow. If not configured a sample of "https://example.com" is
// used.
func (p *TestProvider) SetAllowedRedirectURIs(uris []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedRedirectURIs = uris
}

// SetCustomClaims lets you set claims to return in the JWT issued by the OIDC
// workflow.
func (p *TestProvider) SetCustomClaims(customClaims map[string]interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.customClaims = customClaims
}

// SetCustomAudience configures what audience value to embed in the JWT issued
// by the OIDC workflow.
func (p *TestProvider) SetCustomAudience(customAudience string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.customAudience = customAudience
}

// OmitIDTokens forces an error state where the /token endpoint does not return
// id_token.
func (p *TestProvider) OmitIDTokens() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitIDToken = true
}

// DisableUserInfo makes the userinfo endpoint return 404 and omits it from the
// discovery config.
func (p *TestProvider) DisableUserInfo() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disableUserInfo = true
}

// Addr returns the current base URL for the test provider's running webserver.
func (p *TestProvider) Addr() string { return p.httpServer.URL }

// CACert returns the pem-encoded CA certificate used by the test provider's
// HTTPS server.
func (p *TestProvider) CACert() string { return p.caCert }

// SigningKeys returns the test provider's pem-encoded keys used to sign JWTs.
func (p *TestProvider) SigningKeys() (pub, priv string) {
	return p.ecdsaPublicKey, p.ecdsaPrivateKey
}

func (p *TestProvider) writeJSON(w http.ResponseWriter, out interface{}) error {
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

func (p *TestProvider) writeAuthErrorResponse(w http.ResponseWriter, req *http.Request, errorCode, errorMessage string) {
	qv := req.URL.Query()

	redirectURI := qv.Get("redirect_uri") +
		"?state=" + url.QueryEscape(qv.Get("state")) +
		"&error=" + url.QueryEscape(errorCode)

	if errorMessage != "" {
		redirectURI += "&error_description=" + url.QueryEscape(errorMessage)
	}

	http.Redirect(w, req, redirectURI, http.StatusFound)
}

func (p *TestProvider) writeTokenErrorResponse(w http.ResponseWriter, req *http.Request, statusCode int, errorCode, errorMessage string) error {
	body := struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}{
		Code: errorCode,
		Desc: errorMessage,
	}

	w.WriteHeader(statusCode)
	return p.writeJSON(w, &body)
}

// ServeHTTP implements the test provider's http.Handler.
func (p *TestProvider) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.t.Helper()

	w.Header().Set("Content-Type", "application/json")

	switch req.URL.Path {
	case "/.well-known/openid-configuration":
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		reply := struct {
			Issuer           string `json:"issuer"`
			AuthEndpoint     string `json:"authorization_endpoint"`
			TokenEndpoint    string `json:"token_endpoint"`
			JWKSURI          string `json:"jwks_uri"`
			UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
		}{
			Issuer:           p.Addr(),
			AuthEndpoint:     p.Addr() + "/auth",
			TokenEndpoint:    p.Addr() + "/token",
			JWKSURI:          p.Addr() + "/certs",
			UserinfoEndpoint: p.Addr() + "/userinfo",
		}
		if p.disableUserInfo {
			reply.UserinfoEndpoint = ""
		}

		if err := p.writeJSON(w, &reply); err != nil {
			return
		}

	case "/auth":
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		qv := req.URL.Query()

		if qv.Get("response_type") != "code" {
			p.writeAuthErrorResponse(w, req, "unsupported_response_type", "")
			return
		}
		if qv.Get("scope") != "openid" {
			p.writeAuthErrorResponse(w, req, "invalid_scope", "")
			return
		}

		if p.expectedAuthCode == "" {
			p.writeAuthErrorResponse(w, req, "access_denied", "")
			return
		}

		nonce := qv.Get("nonce")
		if p.expectedAuthNonce != "" && p.expectedAuthNonce != nonce {
			p.writeAuthErrorResponse(w, req, "access_denied", "")
			return
		}

		state := qv.Get("state")
		if state == "" {
			p.writeAuthErrorResponse(w, req, "invalid_request", "missing state parameter")
			return
		}

		redirectURI := qv.Get("redirect_uri")
		if redirectURI == "" {
			p.writeAuthErrorResponse(w, req, "invalid_request", "missing redirect_uri parameter")
			return
		}

		redirectURI += "?state=" + url.QueryEscape(state) +
			"&code=" + url.QueryEscape(p.expectedAuthCode)

		http.Redirect(w, req, redirectURI, http.StatusFound)

		return

	case "/certs":
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := p.writeJSON(w, p.jwks); err != nil {
			return
		}

	case "/certs_missing":
		w.WriteHeader(http.StatusNotFound)

	case "/certs_invalid":
		_, _ = w.Write([]byte("It's not a keyset!"))

	case "/token":
		if req.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		switch {
		case req.FormValue("grant_type") != "authorization_code":
			_ = p.writeTokenErrorResponse(w, req, http.StatusBadRequest, "invalid_request", "bad grant_type")
			return
		case !strutils.StrListContains(p.allowedRedirectURIs, req.FormValue("redirect_uri")):
			_ = p.writeTokenErrorResponse(w, req, http.StatusBadRequest, "invalid_request", "redirect_uri is not allowed")
			return
		case req.FormValue("code") != p.expectedAuthCode:
			_ = p.writeTokenErrorResponse(w, req, http.StatusUnauthorized, "invalid_grant", "unexpected auth code")
			return
		}

		stdClaims := jwt.Claims{
			Subject:   p.replySubject,
			Issuer:    p.Addr(),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Second)),
			Audience:  jwt.Audience{p.clientID},
		}
		if p.customAudience != "" {
			stdClaims.Audience = jwt.Audience{p.customAudience}
		}

		jwtData := TestSignJWT(p.t, p.ecdsaPrivateKey, stdClaims, p.customClaims)

		reply := struct {
			AccessToken string `json:"access_token"`
			IDToken     string `json:"id_token,omitempty"`
		}{
			AccessToken: jwtData,
			IDToken:     jwtData,
		}
		if p.omitIDToken {
			reply.IDToken = ""
		}
		if err := p.writeJSON(w, &reply); err != nil {
			return
		}

	case "/userinfo":
		if p.disableUserInfo {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := p.writeJSON(w, p.replyUserinfo); err != nil {
			return
		}

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// testJWKS converts a pem-encoded public key into JWKS data suitable for a
// verification endpoint response
func testJWKS(t *testing.T, pubKey string) *jose.JSONWebKeySet {
	t.Helper()
	require := require.New(t)

	block, _ := pem.Decode([]byte(pubKey))
	require.NotNil(block)

	input := block.Bytes

	pub, err := x509.ParsePKIXPublicKey(input)
	require.NoError(err)

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: pub,
			},
		},
	}
}

// httptestNewUnstartedServerWithPort is roughly the same as
// httptest.NewUnstartedServer() but allows the caller to explicitly choose the
// port if desired.
func httptestNewUnstartedServerWithPort(t *testing.T, handler http.Handler, port int) *httptest.Server {
	t.Helper()
	require := require.New(t)
	require.NotEmpty(port)

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	l, err := net.Listen("tcp", addr)
	require.NoError(err)

	return &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
}
