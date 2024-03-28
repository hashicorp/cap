// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

func TestImplicit(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	tp := oidc.StartTestProvider(t)
	p := testNewProvider(t, clientID, clientSecret, "http://alice.com", tp)
	rw := &SingleRequestReader{}

	tests := []struct {
		name      string
		p         *oidc.Provider
		rw        RequestReader
		sFn       SuccessResponseFunc
		eFn       ErrorResponseFunc
		wantErr   bool
		wantIsErr error
	}{
		{"valid", p, rw, testSuccessFn, testFailFn, false, nil},
		{"nil-p", nil, rw, testSuccessFn, testFailFn, true, oidc.ErrInvalidParameter},
		{"nil-rw", p, nil, testSuccessFn, testFailFn, true, oidc.ErrInvalidParameter},
		{"nil-sFn", p, rw, nil, testFailFn, true, oidc.ErrInvalidParameter},
		{"nil-eFn", p, rw, testSuccessFn, nil, true, oidc.ErrInvalidParameter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := Implicit(ctx, tt.p, tt.rw, tt.sFn, tt.eFn)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(got)
		})
	}
}

func Test_ImplicitResponses(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	tp := oidc.StartTestProvider(t)
	tp.SetExpectedAuthCode("valid-code")
	callbackSrv := httptest.NewTLSServer(nil)
	defer callbackSrv.Close()

	redirect := callbackSrv.URL
	tp.SetAllowedRedirectURIs([]string{redirect, redirect})

	p := testNewProvider(t, clientID, clientSecret, redirect, tp)

	tests := []struct {
		name                  string
		exp                   time.Duration
		expectedStateOverride string
		readerOverride        RequestReader
		withoutImplicit       bool
		want                  http.HandlerFunc
		wantStatusCode        int
		wantError             bool
		wantRespError         string
		wantRespDescription   string
	}{
		{
			name:           "basic",
			exp:            1 * time.Minute,
			wantStatusCode: http.StatusOK,
		},
		{
			name:                "expired",
			exp:                 1 * time.Nanosecond,
			wantStatusCode:      http.StatusInternalServerError,
			wantError:           true,
			wantRespError:       "internal-callback-error",
			wantRespDescription: "request is expired",
		},
		{
			name:                  "state-not-matching",
			exp:                   1 * time.Minute,
			expectedStateOverride: "not-matching",
			wantStatusCode:        http.StatusInternalServerError,
			wantError:             true,
			wantRespError:         "internal-callback-error",
			wantRespDescription:   "not found",
		},
		{
			name:                "state-returns-nil",
			exp:                 1 * time.Minute,
			readerOverride:      &testNilRequestReader{},
			wantStatusCode:      http.StatusInternalServerError,
			wantError:           true,
			wantRespError:       "internal-callback-error",
			wantRespDescription: "not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			oidcRequest, err := oidc.NewRequest(tt.exp, redirect, oidc.WithImplicitFlow())
			require.NoError(err)

			tp.SetExpectedAuthNonce(oidcRequest.Nonce())

			if tt.expectedStateOverride != "" {
				tp.SetExpectedState(tt.expectedStateOverride)
				defer tp.SetExpectedState("")
			}
			var reader RequestReader
			switch {
			case tt.readerOverride != nil:
				reader = tt.readerOverride
			default:
				reader = &SingleRequestReader{oidcRequest}
			}
			callbackSrv.Config.Handler, err = Implicit(ctx, p, reader, testSuccessFn, testFailFn)
			require.NoError(err)

			authURL, err := p.AuthURL(ctx, oidcRequest)
			require.NoError(err)

			// the TestProvider is returning an html form which is posted
			// "onload", which assumes a browser client, so we have to pretend
			// to be a browser and post the form to the callback.
			// For implicit form_post response example:
			// https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
			resp := testPostFormToCallback(t, tp, authURL)
			defer resp.Body.Close()
			contents, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)

			assert.Equal(tt.wantStatusCode, resp.StatusCode)
			if tt.wantError {
				var errResp AuthenErrorResponse
				require.NoError(json.Unmarshal(contents, &errResp))
				assert.Equal(tt.wantRespError, errResp.Error)
				if tt.wantRespDescription != "" {
					assert.Contains(errResp.Description, tt.wantRespDescription)
				}
				return
			}
			assert.Contains(string(contents), `login successful`)
		})
	}
	t.Run("authen-error", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		req, err := oidc.NewRequest(1*time.Minute, redirect, oidc.WithImplicitFlow())
		require.NoError(err)
		tp.SetExpectedAuthNonce(req.Nonce())
		reader := &SingleRequestReader{req}
		callbackSrv.Config.Handler, err = Implicit(ctx, p, reader, testSuccessFn, testFailFn)
		require.NoError(err)

		tp.SetDisableImplicit(true)
		defer tp.SetDisableImplicit(false)

		// For this sort of authentication error, the TestProvider returns a
		// redirect (not the typical html response with a form to be posted by
		// the browser onload)
		authURL, err := p.AuthURL(ctx, req)
		require.NoError(err)
		resp, err := tp.HTTPClient().Get(authURL)
		require.NoError(err)
		assert.NotEmpty(resp)
		defer resp.Body.Close()
		contents, err := ioutil.ReadAll(resp.Body)
		require.NoError(err)

		var errResp AuthenErrorResponse
		require.NoError(json.Unmarshal(contents, &errResp))
		assert.Equal("access_denied", errResp.Error)
	})
	t.Run("signing-error", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		priv, pub, alg, keyID := tp.SigningKeys()
		defer tp.SetSigningKeys(priv, pub, alg, keyID)

		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(err)
		tp.SetSigningKeys(k, k.Public(), oidc.ES384, "new-key")

		req, err := oidc.NewRequest(1*time.Minute, redirect, oidc.WithImplicitFlow())
		require.NoError(err)
		tp.SetExpectedAuthNonce(req.Nonce())
		reader := &SingleRequestReader{req}
		callbackSrv.Config.Handler, err = Implicit(ctx, p, reader, testSuccessFn, testFailFn)
		require.NoError(err)

		authURL, err := p.AuthURL(ctx, req)
		require.NoError(err)

		// the TestProvider is returning an html form which is posted
		// "onload", which assumes a browser client, so we have to pretend
		// to be a browser and post the form to the callback.
		// For implicit form_post response example:
		// https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
		resp := testPostFormToCallback(t, tp, authURL)
		defer resp.Body.Close()

		contents, err := ioutil.ReadAll(resp.Body)
		require.NoError(err)

		var errResp AuthenErrorResponse
		require.NoError(json.Unmarshal(contents, &errResp))
		assert.Equal("internal-callback-error", errResp.Error)
		assert.Contains(errResp.Description, "unsupported signing algorithm")
	})
	t.Run("not-implicit-flow", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		oidcReq, err := oidc.NewRequest(1*time.Minute, redirect)
		require.NoError(err)
		reader := &SingleRequestReader{oidcReq}
		handler, err := Implicit(ctx, p, reader, testSuccessFn, testFailFn)
		require.NoError(err)

		reqForm := url.Values{}
		reqForm.Add("state", oidcReq.State())
		reqForm.Add("id_token", "dummy-token")

		req, err := http.NewRequest("POST", "/callback", strings.NewReader(reqForm.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(err)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		contents, err := ioutil.ReadAll(rr.Body)
		require.NoError(err)

		var errResp AuthenErrorResponse
		require.NoError(json.Unmarshal(contents, &errResp))
		assert.Equal("internal-callback-error", errResp.Error)
		assert.Contains(errResp.Description, "invalid OIDC flow")
	})
}

// testPostFormToCallback is a helper that supports the TestProvider is
// returning an html form which is posted "onload", which assumes a browser
// client, so we have to pretend to be a browser and post the form to the
// callback.
func testPostFormToCallback(t *testing.T, tp *oidc.TestProvider, authURL string) *http.Response {
	t.Helper()
	assert, require := assert.New(t), require.New(t)

	resp, err := tp.HTTPClient().Get(authURL)
	require.NoError(err)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		contents, err := ioutil.ReadAll(resp.Body)
		require.NoError(err)
		t.Log("unexpected resp status code: resp contents: ", string(contents))
		require.Equal(http.StatusOK, resp.StatusCode)
	}
	require.Equal(http.StatusOK, resp.StatusCode)

	// For implicit form_post response example:
	// https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
	root, err := html.Parse(resp.Body)
	require.NoError(err)
	defer resp.Body.Close()
	form, ok := scrape.Find(root, scrape.ByTag(atom.Form))
	require.True(ok)
	require.Equal("post", scrape.Attr(form, "method"))
	action := scrape.Attr(form, "action")
	require.NotEmpty(action)

	sNode, ok := scrape.Find(form, scrape.ById("state"))
	require.True(ok)
	formState := scrape.Attr(sNode, "value")
	require.NotEmpty(formState)

	idNode, ok := scrape.Find(form, scrape.ById("id_token"))
	require.True(ok)
	formIdTk := scrape.Attr(idNode, "value")
	require.NotEmpty(formIdTk)

	acNode, ok := scrape.Find(form, scrape.ById("access_token"))
	require.True(ok)
	formAcTk := scrape.Attr(acNode, "value")
	require.NotEmpty(formAcTk)

	reqForm := url.Values{}
	reqForm.Add("state", formState)
	reqForm.Add("access_token", formAcTk)
	reqForm.Add("id_token", formIdTk)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	callbackClient := http.Client{Transport: tr}
	req, err := http.NewRequest("POST", action, strings.NewReader(reqForm.Encode()))
	require.NoError(err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = callbackClient.Do(req)
	require.NoError(err)
	assert.NotEmpty(resp)
	return resp
}
