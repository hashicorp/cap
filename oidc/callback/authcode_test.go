// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCode(t *testing.T) {
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
			got, err := AuthCode(ctx, tt.p, tt.rw, tt.sFn, tt.eFn)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(got)
		})
	}
}

func Test_AuthCodeResponses(t *testing.T) {
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
		name                string
		exp                 time.Duration
		nonceOverride       string
		stateOverride       string
		readerOverride      RequestReader
		disableExchange     bool
		want                http.HandlerFunc
		wantStatusCode      int
		wantError           bool
		wantRespError       string
		wantRespDescription string
	}{
		{
			name:           "basic",
			exp:            1 * time.Minute,
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "bad-nonce",
			exp:            1 * time.Minute,
			nonceOverride:  "bad-nonce",
			wantStatusCode: http.StatusUnauthorized,
			wantError:      true,
			wantRespError:  "access_denied",
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
			name:                "state-not-matching",
			exp:                 1 * time.Minute,
			stateOverride:       "not-matching",
			wantStatusCode:      http.StatusInternalServerError,
			wantError:           true,
			wantRespError:       "internal-callback-error",
			wantRespDescription: "not found",
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
		{
			name:                "bad-exchange",
			exp:                 1 * time.Minute,
			disableExchange:     true,
			wantStatusCode:      http.StatusInternalServerError,
			wantError:           true,
			wantRespError:       "internal-callback-error",
			wantRespDescription: "Unauthorized\nResponse",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			oidcRequest, err := oidc.NewRequest(tt.exp, redirect)
			require.NoError(err)

			switch {
			case tt.nonceOverride != "":
				tp.SetExpectedAuthNonce(tt.nonceOverride)
			default:
				tp.SetExpectedAuthNonce(oidcRequest.Nonce())
			}

			if tt.stateOverride != "" {
				tp.SetExpectedState(tt.stateOverride)
				defer tp.SetExpectedState("")
			}
			if tt.disableExchange {
				tp.SetDisableToken(true)
				defer tp.SetDisableToken(false)
			}
			var reader RequestReader
			switch {
			case tt.readerOverride != nil:
				reader = tt.readerOverride
			default:
				reader = &SingleRequestReader{oidcRequest}
			}
			callbackSrv.Config.Handler, err = AuthCode(ctx, p, reader, testSuccessFn, testFailFn)
			require.NoError(err)

			authURL, err := p.AuthURL(ctx, oidcRequest)
			require.NoError(err)

			resp, err := tp.HTTPClient().Get(authURL)
			require.NoError(err)
			contents, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)
			defer resp.Body.Close()

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
			assert.Equal("login successful", string(contents))
		})
	}
}
