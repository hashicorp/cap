// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azure

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// testRoundTripper is a function type that implements http.RoundTripper,
// allowing tests to supply mocked HTTP responses via a closure.
type testRoundTripper func(r *http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// testGraphClient returns an *http.Client whose transport returns a canned
// HTTP response with the provided status code and body.
func testGraphClient(status int, body string) *http.Client {
	return &http.Client{
		Transport: testRoundTripper(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
}

// testOverageClaims returns a mocked set of overage claims for the provided
// graph API host.
func testOverageClaims(t *testing.T, host string) map[string]any {
	t.Helper()
	require.NotEmptyf(t, host, "graph API host must be provided")

	return map[string]any{
		claimNameField: map[string]any{
			claimGroupsField: "src1",
		},
		claimSourceField: map[string]any{
			"src1": map[string]any{
				claimEndpointField: fmt.Sprintf("https://%s%s", host, getMemberObjectsPath),
			},
		},
	}
}

func Test_KnownGraphHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		host string
		want bool
	}{
		{
			name: "empty host",
			host: "",
			want: false,
		},
		{
			name: "unknown host",
			host: "unknown.host.com",
			want: false,
		},
		{
			name: "Azure AD Graph host",
			host: azureADGraphHost,
			want: true,
		},
		{
			name: "Azure AD Graph US host",
			host: azureADGraphUSHost,
			want: true,
		},
		{
			name: "Azure AD Graph CN host",
			host: azureADGraphCNHost,
			want: true,
		},
		{
			name: "Microsoft Graph host",
			host: microsoftGraphHost,
			want: true,
		},
		{
			name: "Microsoft Graph US host",
			host: microsoftGraphUSHost,
			want: true,
		},
		{
			name: "Microsoft Graph US DoD host",
			host: microsoftGraphUSDodHost,
			want: true,
		},
		{
			name: "Microsoft Graph CN host",
			host: microsoftGraphCNHost,
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := knownGraphHost(tc.host)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_FetchGroupsOverageHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		claims       map[string]any
		want         bool
		expectedHost string
	}{
		{
			name:         "nil claims",
			claims:       nil,
			want:         false,
			expectedHost: "",
		},
		{
			name:         "empty claims",
			claims:       map[string]any{},
			want:         false,
			expectedHost: "",
		},
		{
			name: "missing claim names field",
			claims: map[string]any{
				claimNameField: nil,
			},
			want:         false,
			expectedHost: "",
		},
		{
			name: "missing claim groups field",
			claims: map[string]any{
				claimNameField: map[string]any{
					claimGroupsField: nil,
				},
			},
			want:         false,
			expectedHost: "",
		},
		{
			name: "missing claim source field",
			claims: map[string]any{
				claimNameField: map[string]any{
					claimGroupsField: "src1",
				},
			},
			want:         false,
			expectedHost: "",
		},
		{
			name: "missing source key field",
			claims: map[string]any{
				claimNameField: map[string]any{
					claimGroupsField: "src1",
				},
				claimSourceField: map[string]any{},
			},
			want:         false,
			expectedHost: "",
		},
		{
			name: "missing endpoint field",
			claims: map[string]any{
				claimNameField: map[string]any{
					claimGroupsField: "src1",
				},
				claimSourceField: map[string]any{
					"src1": map[string]any{},
				},
			},
			want:         false,
			expectedHost: "",
		},
		{
			name: "invalid endpoint url",
			claims: map[string]any{
				claimNameField: map[string]any{
					claimGroupsField: "src1",
				},
				claimSourceField: map[string]any{
					"src1": map[string]any{
						claimEndpointField: "://bad-url",
					},
				},
			},
			want:         false,
			expectedHost: "",
		},
		{
			name:         "unknown graph host",
			claims:       testOverageClaims(t, "unknown.host.com"),
			want:         false,
			expectedHost: "",
		},
		{
			name:         "valid graph API host",
			claims:       testOverageClaims(t, microsoftGraphHost),
			want:         true,
			expectedHost: microsoftGraphHost,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			host, ok := fetchGroupsOverageHost(tc.claims)
			if !tc.want {
				require.False(t, ok)
				assert.Empty(t, host)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.expectedHost, host)
		})
	}
}

func Test_GraphGroupsEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		host         string
		wantErr      error
		wantEndpoint *url.URL
	}{
		{
			name:         "empty host",
			host:         "",
			wantErr:      ErrInvalidParameter,
			wantEndpoint: nil,
		},
		{
			name:         "unknown host",
			host:         "unknown.host.com",
			wantErr:      ErrInvalidParameter,
			wantEndpoint: nil,
		},
		{
			name: "valid graph API host",
			host: "graph.microsoft.com",
			wantEndpoint: func() *url.URL {
				u, err := url.Parse(fmt.Sprintf("https://%s%s", microsoftGraphHost, getMemberObjectsPath))
				require.NoError(t, err)
				return u
			}(),
		},
		{
			name: "valid deprecated graph API host",
			host: "graph.windows.net",
			wantEndpoint: func() *url.URL {
				u, err := url.Parse(fmt.Sprintf("https://%s%s", microsoftGraphHost, getMemberObjectsPath))
				require.NoError(t, err)
				return u
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			endpoint, err := graphGroupsEndpoint(tc.host)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, endpoint)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantEndpoint, endpoint)
		})
	}
}

func Test_FetchGroupIDs(t *testing.T) {
	t.Parallel()

	testToken := &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(10 * time.Second),
	}

	testEndpoint, err := url.Parse(fmt.Sprintf("https://%s%s", microsoftGraphHost, getMemberObjectsPath))
	require.NoError(t, err)

	testCases := []struct {
		name       string
		client     *http.Client
		token      *oauth2.Token
		endpoint   *url.URL
		wantErr    bool
		wantErrIs  error
		wantErrMsg string
		wantGroups []string
	}{
		{
			name:       "missing http client",
			wantErr:    true,
			wantErrIs:  ErrNilParameter,
			wantErrMsg: "nil http client",
		},
		{
			name:       "missing oauth2 token",
			client:     http.DefaultClient,
			wantErr:    true,
			wantErrIs:  ErrNilParameter,
			wantErrMsg: "nil oauth2 token",
		},
		{
			name:       "missing endpoint",
			client:     http.DefaultClient,
			token:      testToken,
			wantErr:    true,
			wantErrIs:  ErrInvalidParameter,
			wantErrMsg: "missing endpoint",
		},
		{
			name:       "unauthorized response",
			client:     testGraphClient(http.StatusUnauthorized, ""),
			token:      testToken,
			endpoint:   testEndpoint,
			wantErr:    true,
			wantErrMsg: "graph API request failed with status 401",
		},
		{
			name:       "bad response body",
			client:     testGraphClient(http.StatusOK, "invalid json response data"),
			token:      testToken,
			endpoint:   testEndpoint,
			wantErr:    true,
			wantErrMsg: "failed to unmarshal the graph API response body",
		},
		{
			name:       "valid response",
			client:     testGraphClient(http.StatusOK, `{"value":["group1","group2"]}`),
			token:      testToken,
			endpoint:   testEndpoint,
			wantGroups: []string{"group1", "group2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := fetchGroupIDs(t.Context(), tc.client, tc.token, tc.endpoint)
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(t, err, tc.wantErrIs)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tc.wantGroups, res)
		})
	}
}

func Test_ResolveGroupClaims(t *testing.T) {
	t.Parallel()

	testToken := &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(10 * time.Second),
	}

	testCases := []struct {
		name       string
		client     *http.Client
		token      *oauth2.Token
		claims     map[string]any
		wantErr    bool
		wantErrIs  error
		wantErrMsg string
		wantClaims map[string]any
	}{
		{
			name:       "nil http client",
			token:      testToken,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantErr:    true,
			wantErrIs:  ErrNilParameter,
			wantErrMsg: "nil http client",
		},
		{
			name:       "nil oauth2 token",
			client:     http.DefaultClient,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantErr:    true,
			wantErrIs:  ErrNilParameter,
			wantErrMsg: "nil oauth2 token",
		},
		{
			name:       "nil claims map",
			client:     http.DefaultClient,
			token:      testToken,
			wantErr:    true,
			wantErrIs:  ErrNilParameter,
			wantErrMsg: "nil claims map",
		},
		{
			name:       "empty claims",
			client:     http.DefaultClient,
			token:      testToken,
			claims:     map[string]any{},
			wantClaims: map[string]any{},
		},
		{
			name:       "no overage claim",
			client:     http.DefaultClient,
			token:      testToken,
			claims:     map[string]any{"sub": "user1"},
			wantClaims: map[string]any{},
		},
		{
			name:       "graph API unauthorized",
			client:     testGraphClient(http.StatusUnauthorized, ""),
			token:      testToken,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantErr:    true,
			wantErrMsg: "failed to fetch group IDs from graph API",
		},
		{
			name:       "graph API invalid body",
			client:     testGraphClient(http.StatusOK, "not json"),
			token:      testToken,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantErr:    true,
			wantErrMsg: "failed to fetch group IDs from graph API",
		},
		{
			name:       "graph API returns no groups",
			client:     testGraphClient(http.StatusOK, `{"value":[]}`),
			token:      testToken,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantClaims: map[string]any{"groups": []string{}},
		},
		{
			name:       "graph API returns groups",
			client:     testGraphClient(http.StatusOK, `{"value":["g1","g2"]}`),
			token:      testToken,
			claims:     testOverageClaims(t, microsoftGraphHost),
			wantClaims: map[string]any{"groups": []string{"g1", "g2"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := ResolveGroupClaims(t.Context(), tc.client, tc.token, tc.claims)
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(t, err, tc.wantErrIs)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)
			assert.EqualValues(t, tc.wantClaims, res)
		})
	}
}
