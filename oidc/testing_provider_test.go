package oidc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StartTestProvider(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := func() int {
			addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
			require.NoError(err)
			l, err := net.ListenTCP("tcp", addr)
			require.NoError(err)
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port
		}()

		tp := StartTestProvider(t, WithTestPort(port))
		url, err := url.Parse(tp.Addr())
		require.NoError(err)
		assert.Equal(strconv.Itoa(port), url.Port())

		client := tp.HTTPClient()
		resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
		require.NoError(err)
		assert.Equal(http.StatusOK, resp.StatusCode)
	})
	t.Run("WithNoTLS", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t, WithNoTLS())
		url, err := url.Parse(tp.Addr())
		require.NoError(err)
		assert.Equalf("http", url.Scheme, "expected http and got: %s", url.Scheme)

		client := tp.HTTPClient()
		resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
		require.NoError(err)
		assert.Equal(http.StatusOK, resp.StatusCode)
	})
	t.Run("WithTestingLogger", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		l, err := NewTestingLogger(hclog.New(nil))
		require.NoError(err)
		tp := StartTestProvider(l)
		client := tp.HTTPClient()
		resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
		require.NoError(err)
		assert.Equal(http.StatusOK, resp.StatusCode)
	})
}

func Test_HTTPClient(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	tp := StartTestProvider(t)
	client := tp.HTTPClient()
	assert.Equal(tp.client, client)
	resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
	require.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
}
func Test_WithTestPort(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getTestProviderOpts(t, WithTestPort(8080))
	testOpts := testProviderDefaults(t)
	testOpts.withDefaults.PKCEVerifier = opts.withDefaults.PKCEVerifier

	// funcs are difficult to compare, so we'll special case them
	testAssertEqualFunc(t, opts.withDefaults.NowFunc, testOpts.withDefaults.NowFunc, "not equal")
	opts.withDefaults.NowFunc = nil
	testOpts.withDefaults.NowFunc = nil

	// keys are generated for default opts, so let's handle that
	testOpts.withDefaults.SigningKey.PrivKey = opts.withDefaults.SigningKey.PrivKey
	testOpts.withDefaults.SigningKey.PubKey = opts.withDefaults.SigningKey.PubKey
	testOpts.withPort = 8080
	assert.Equal(opts, testOpts)
}

func TestTestProvider_SetSupportedScopes(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Contains(tp.supportedScopes, "openid")
		tp.SetSupportedScopes("email", "profile")
		assert.Contains(tp.supportedScopes, "openid")
		assert.Contains(tp.supportedScopes, "email")
		assert.Contains(tp.supportedScopes, "profile")
	})
}

func TestTestProvider_SetExpectedSubject(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.ExpectedSubject(), "alice@example.com")
		tp.SetExpectedSubject("eve@example.com")
		assert.Equal("eve@example.com", tp.ExpectedSubject())
	})
}

func TestTestProvider_SetExpectedExpiry(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.replyExpiry, 5*time.Second)
		tp.SetExpectedExpiry(5 * time.Minute)
		assert.Equal(5*time.Minute, tp.replyExpiry)
	})
}
func TestTestProvider_SetClientCreds(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Empty(tp.clientID)
		require.Empty(tp.clientSecret)
		tp.SetClientCreds("alice", "bob")
		gotClientID, gotClientSecret := tp.ClientCreds()
		assert.Equal("alice", gotClientID)
		assert.Equal("bob", gotClientSecret)
	})
}

func TestTestProvider_SetExpectedAuthCode(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Empty(tp.expectedAuthCode)
		tp.SetExpectedAuthCode("blue")
		assert.Equal("blue", tp.expectedAuthCode)
	})
}
func TestTestProvider_SetExpectedAuthNonce(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Empty(tp.expectedAuthNonce)
		tp.SetExpectedAuthNonce("red")
		assert.Equal("red", tp.expectedAuthNonce)
	})
}

func TestTestProvider_SetAllowedRedirectURIs(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal([]string{"https://example.com"}, tp.allowedRedirectURIs)
		tp.SetAllowedRedirectURIs([]string{"https://shoe.com", "https://pants.com"})
		assert.Equal([]string{"https://shoe.com", "https://pants.com"}, tp.allowedRedirectURIs)
	})
}

func TestTestProvider_SetCustomClaims(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(map[string]interface{}{"email": "alice@example.com", "name": "Alice Doe Smith"}, tp.customClaims)
		custom := map[string]interface{}{"what_is_your_favorite_color": "blue... no green!"}
		tp.SetCustomClaims(custom)
		assert.Equal(custom, tp.customClaims)
	})
}

func TestTestProvider_SetCustomAudience(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(0, len(tp.customAudiences))
		tp.SetCustomAudience("alice", "bob", "eve")
		assert.Equal([]string{"alice", "bob", "eve"}, tp.customAudiences)
	})
}

func TestTestProvider_SetNowFunc(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		tp := StartTestProvider(t)
		testAssertEqualFunc(t, time.Now, time.Now, "not equal")
		tFn := func() time.Time { return time.Now().Add(-1 * time.Hour) }
		tp.SetNowFunc(tFn)
		testAssertEqualFunc(t, tFn, tp.nowFunc, "not equal")
	})
}

func TestTestProvider_SetOmitAuthTimeClaim(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.omitAuthTimeClaim, false)
		tp.SetOmitAuthTimeClaim(true)
		assert.Equal(true, tp.omitAuthTimeClaim)
	})
}

func TestTestProvider_SetOmitIDTokens(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.omitIDToken, false)
		tp.SetOmitIDTokens(true)
		assert.Equal(true, tp.omitIDToken)
	})
}
func TestTestProvider_SetOmitAccessTokens(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.omitAccessToken, false)
		tp.SetOmitAccessTokens(true)
		assert.Equal(true, tp.omitAccessToken)
	})
}

func TestTestProvider_SetDisableUserInfo(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.disableUserInfo, false)
		tp.SetDisableUserInfo(true)
		assert.Equal(true, tp.disableUserInfo)
	})
}

func TestTestProvider_SetDisableJWKs(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.disableJWKs, false)
		tp.SetDisableJWKs(true)
		assert.Equal(true, tp.disableJWKs)
	})
}

func TestTestProvider_SetInvalidJWKS(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.invalidJWKs, false)
		tp.SetInvalidJWKS(true)
		assert.Equal(true, tp.invalidJWKs)
	})
}

func TestTestProvider_SetSigningKeys(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert := assert.New(t)
		tp := StartTestProvider(t)
		pub, priv := TestGenerateKeys(t)
		tp.SetSigningKeys(priv, pub, RS256, "test-key-id")

		gotPriv, gotPub, gotAlg, gotKeyID := tp.SigningKeys()
		assert.Equal(priv, gotPriv)
		assert.Equal(pub, gotPub)
		assert.Equal(RS256, gotAlg)
		assert.Equal("test-key-id", gotKeyID)
	})
}

func TestTestProvider_SetDisableImplicit(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.disableImplicit, false)
		tp.SetDisableImplicit(true)
		assert.Equal(true, tp.disableImplicit)
	})
}

func TestTestProvider_SetDisableToken(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.disableToken, false)
		tp.SetDisableToken(true)
		assert.Equal(true, tp.disableToken)
	})
}

func TestTestProvider_SetExpectedState(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		require.Equal(tp.expectedState, "")
		tp.SetExpectedState("expected")
		assert.Equal("expected", tp.expectedState)
	})
}

func TestTestProvider_SetPKCEVerifier(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		v, err := NewCodeVerifier()
		require.NoError(err)
		tp.SetPKCEVerifier(v)
		assert.Equal(v, tp.pkceVerifier)
		assert.Equal(v, tp.PKCEVerifier())
	})
}

func TestTestProvider_SetUserInfoReply(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert := assert.New(t)
		tp := StartTestProvider(t)
		reply := map[string]interface{}{
			"sub": "alice",
		}
		tp.SetUserInfoReply(reply)
		assert.Equal(reply, tp.replyUserinfo)
		assert.Equal(reply, tp.UserInfoReply())
	})
}

func TestTestProvider_writeJSON(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		data := map[string]string{
			"FirstName": "jane",
			"LastName":  "doe",
		}
		rr := httptest.NewRecorder()
		err := tp.writeJSON(rr, data)
		require.NoError(err)
		// Check the response body is what we expect.
		expected := `{"FirstName":"jane","LastName":"doe"}`
		got := strings.TrimSuffix(rr.Body.String(), "\n")
		assert.Equal(expected, got)
	})
}

func TestTestProvider_writeImplicitResponse(t *testing.T) {
	t.Run("include-tokens", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		rr := httptest.NewRecorder()
		err := tp.writeImplicitResponse(rr, "valid-state", "http://localhost:8080/")
		require.NoError(err)
		assert.Contains(rr.Body.String(), `input type="hidden" name="access_token"`)
		assert.Contains(rr.Body.String(), `input type="hidden" name="id_token"`)
	})
	t.Run("no-tokens", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		tp.SetOmitAccessTokens(true)
		tp.SetOmitIDTokens(true)
		rr := httptest.NewRecorder()
		err := tp.writeImplicitResponse(rr, "valid-state", "http://localhost:8080/")
		require.NoError(err)
		assert.NotContains(rr.Body.String(), `input type="hidden" name="access_token"`)
		assert.NotContains(rr.Body.String(), `input type="hidden" name="id_token"`)
	})
}

func TestTestProvider_writeAuthErrorResponse(t *testing.T) {
	tp := StartTestProvider(t)
	type body struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rr := httptest.NewRecorder()
		url, err := url.Parse("https://example.com/callback")
		require.NoError(err)
		req := http.Request{
			Method: "GET",
			URL:    url,
		}
		tp.writeAuthErrorResponse(rr, &req, "redirectURL", "state", "error_code", "error_message")
		assert.Equal(rr.Result().StatusCode, 302)

		location, err := rr.Result().Location()
		require.NoError(err)
		assert.Equal("/redirectURL?state=state&error=error_code&error_description=error_message", location.String())
	})
}
func TestTestProvider_writeTokenErrorResponse(t *testing.T) {
	tp := StartTestProvider(t)
	type body struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}
	t.Run("include-desc", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rr := httptest.NewRecorder()
		err := tp.writeTokenErrorResponse(rr, 401, "error_code", "error_message")
		require.NoError(err)
		var errBody body
		err = json.Unmarshal(rr.Body.Bytes(), &errBody)
		require.NoError(err)
		assert.Equal("error_code", errBody.Code)
		assert.Equal("error_message", errBody.Desc)
	})
	t.Run("no-desc", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rr := httptest.NewRecorder()
		err := tp.writeTokenErrorResponse(rr, 401, "error_code", "")
		require.NoError(err)
		var errBody body
		err = json.Unmarshal(rr.Body.Bytes(), &errBody)
		require.NoError(err)
		assert.Equal("error_code", errBody.Code)
		assert.Empty(errBody.Desc)
	})
}

func TestTestProvider_authorize(t *testing.T) {
	tp := StartTestProvider(t)
	echo := startEchoServer(t)
	type errResp struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}
	tests := []struct {
		name          string
		urlParameters string
		want          string
	}{
		{
			name:          "bad-response-type",
			urlParameters: "&response_type=unknown&state=state-value",
			want:          "unsupported_response_type",
		},
		{
			name:          "bad-scopes",
			urlParameters: "&scope=unknown&state=state-value&response_type=code",
			want:          "invalid_scope",
		},
		{
			name:          "bad-auth-code",
			urlParameters: "&code=bad-auth-code&scope=openid&state=state-value&response_type=code",
			want:          "access_denied",
		},
		{
			name:          "bad-nonce",
			urlParameters: "&nonce=bad-nonce&code=valid-code&scope=openid&state=state-value&response_type=code",
			want:          "access_denied",
		},
		{
			name:          "empty-state",
			urlParameters: "&nonce=valid-nonce&code=valid-code&scope=openid&response_type=code",
			want:          "missing+state+parameter",
		},
		{
			name:          "bad-resp-mode",
			urlParameters: "&response_type=id_token&response_mode=unknown&state=valid-state&nonce=valid-nonce&code=valid-code&scope=openid&response_type=code",
			want:          "unsupported_response_mode",
		},
		{
			name:          "valid",
			urlParameters: "&state=valid-state&nonce=valid-nonce&code=valid-code&scope=openid&response_type=code",
			want:          "GET /?state=valid-state&code=valid-code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tp.SetExpectedAuthCode("valid-code")
			tp.SetExpectedAuthNonce("valid-nonce")
			client := tp.HTTPClient()
			url := fmt.Sprintf("%s/authorize?redirect_uri=%s%s", tp.Addr(), echo.URL, tt.urlParameters)
			resp, err := client.Get(url)
			require.NoError(err)
			assert.NotEmpty(resp)
			defer resp.Body.Close()
			contents, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)
			assert.Contains(string(contents), tt.want)
		})
	}
	t.Run("bad-method", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		client := tp.HTTPClient()
		req, err := http.NewRequest(http.MethodPut, tp.Addr()+"/authorize", nil)
		require.NoError(err)
		resp, err := client.Do(req)
		require.NoError(err)
		assert.Equal(http.StatusMethodNotAllowed, resp.StatusCode)
	})
}

func TestTestProvider_token(t *testing.T) {
	tp := StartTestProvider(t)
	echo := startEchoServer(t)

	type payload struct {
		code        string
		grantType   string
		redirectURI string
	}
	type errResp struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}
	tests := []struct {
		name               string
		payload            payload
		allowedRedirectURI string
		wantErrStatus      int
	}{
		{
			name: "valid",
			payload: payload{
				redirectURI: echo.URL,
				grantType:   "authorization_code",
				code:        "valid-code",
			},
			allowedRedirectURI: echo.URL,
		},
		{
			name: "empty-code",
			payload: payload{
				redirectURI: echo.URL,
				grantType:   "authorization_code",
			},
			allowedRedirectURI: echo.URL,
			wantErrStatus:      http.StatusUnauthorized,
		},
		{
			name: "bad-code",
			payload: payload{
				redirectURI: echo.URL,
				grantType:   "authorization_code",
				code:        "bad-code",
			},
			allowedRedirectURI: echo.URL,
			wantErrStatus:      http.StatusUnauthorized,
		},
		{
			name: "bad-redirect",
			payload: payload{
				redirectURI: echo.URL,
				grantType:   "authorization_code",
				code:        "valid-code",
			},
			allowedRedirectURI: "http://alice.com",
			wantErrStatus:      http.StatusBadRequest,
		},
		{
			name: "valid",
			payload: payload{
				redirectURI: echo.URL,
				grantType:   "unknown",
				code:        "valid-code",
			},
			allowedRedirectURI: echo.URL,
			wantErrStatus:      http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tp.SetExpectedAuthCode("valid-code")
			tp.SetAllowedRedirectURIs([]string{tt.allowedRedirectURI})
			client := tp.HTTPClient()
			form := url.Values{}
			form.Add("redirect_uri", tt.payload.redirectURI)
			form.Add("grant_type", tt.payload.grantType)
			form.Add("code", tt.payload.code)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/token", tp.Addr()), strings.NewReader(form.Encode()))
			require.NoError(err)
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			require.NoError(err)
			assert.NotEmpty(resp)
			defer resp.Body.Close()
			if tt.wantErrStatus != 0 {
				assert.Equal(tt.wantErrStatus, resp.StatusCode)
				return
			}
			contents, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)
			type successResp struct {
				Id_token string
			}
			var got successResp
			err = json.Unmarshal(contents, &got)
			require.NoError(err)
			assert.NotEmpty(got.Id_token)
		})
	}
}

func TestTestProvider_discovery(t *testing.T) {
	t.Run("/.well-known/openid-configuration", func(t *testing.T) {
		const openidConfiguration = "/.well-known/openid-configuration"
		assert, require := assert.New(t), require.New(t)
		tp := StartTestProvider(t)
		providerAddr := tp.Addr()
		_, _, signingAlg, _ := tp.SigningKeys()
		tp.SupportedScopes()

		resp, err := tp.HTTPClient().Get(tp.Addr() + openidConfiguration)
		require.NoError(err)
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(err)

		reply := struct {
			Issuer                 string   `json:"issuer"`
			AuthEndpoint           string   `json:"authorization_endpoint"`
			TokenEndpoint          string   `json:"token_endpoint"`
			JWKSURI                string   `json:"jwks_uri"`
			UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
			SupportedAlgs          []string `json:"id_token_signing_alg_values_supported"`
			SupportedScopes        []string `json:"scopes_supported"`
			SubjectTypesSupported  []string `json:"subject_types_supported"`
			ResponseTypesSupported []string `json:"response_types_supported"`
		}{}
		err = json.Unmarshal(body, &reply)
		require.NoError(err)
		assert.Equal(providerAddr, reply.Issuer)
		assert.Equal(providerAddr+"/authorize", reply.AuthEndpoint)
		assert.Equal(providerAddr+"/token", reply.TokenEndpoint)
		assert.Equal(providerAddr+"/.well-known/jwks.json", reply.JWKSURI)
		assert.Equal(providerAddr+"/userinfo", reply.UserinfoEndpoint)
		assert.Equal([]string{string(signingAlg)}, reply.SupportedAlgs)
		assert.Equal(tp.SupportedScopes(), reply.SupportedScopes)
		assert.Equal([]string{"public"}, reply.SubjectTypesSupported)
		assert.Equal([]string{"code", "id_token", "token id_token"}, reply.ResponseTypesSupported)
	})
}

// startEchoServer starts a test echo http server which will be stopped when the
// test and its subtests are completed by function registered with t.Cleanup
func startEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Range, Content-Disposition, Content-Type, ETag")
		_ = req.Write(w)
	}))
	t.Cleanup(s.Close)
	return s
}
