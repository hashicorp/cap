package oidc

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StartTestProvider(t *testing.T) {
	t.Parallel()
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

	client := tp.HttpClient()
	resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
	require.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
}

func Test_HttpClient(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	tp := StartTestProvider(t)
	client := tp.HttpClient()
	assert.Equal(tp.client, client)
	resp, err := client.Get(tp.Addr() + "/.well-known/jwks.json")
	require.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
}
func Test_WithTestPort(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getTestProviderOpts(WithTestPort(8080))
	testOpts := testProviderDefaults()
	testOpts.withPort = 8080
	assert.Equal(opts, testOpts)
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
		require.Equal(map[string]interface{}{}, tp.customClaims)
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

		gotPriv, gotPub, gotAlg := tp.SigningKeys()
		assert.Equal(priv, gotPriv)
		assert.Equal(pub, gotPub)
		assert.Equal(RS256, gotAlg)
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
		err := tp.writeImplicitResponse(rr)
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
		err := tp.writeImplicitResponse(rr)
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
