// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = RedactedClientSecret
		secret := ClientSecret("bob's phone number")
		assert.Equalf(want, secret.String(), "ClientSecret.String() = %v, want %v", secret.String(), want)
	})
}

func TestClientSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, RedactedClientSecret)
		secret := ClientSecret("bob's phone number")
		got, err := secret.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "ClientSecret.MarshalJSON() = %s, want %s", got, want)
	})
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	_, testCaPem := TestGenerateCA(t, []string{"localhost"})
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}

	testRt := newTestRoundTripper(t)

	type args struct {
		issuer              string
		clientID            string
		clientSecret        ClientSecret
		supported           []Alg
		allowedRedirectURLs []string
		opt                 []Option
	}
	tests := []struct {
		name            string
		args            args
		want            *Config
		wantErr         bool
		wantIsErr       error
		wantErrContains string
	}{
		{
			name: "valid-with-all-valid-opts-except-with-round-tripper",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url", "http://redirect_url_two", "http://redirect_url_three"},
				opt: []Option{
					WithAudiences("your_aud1", "your_aud2"),
					WithScopes("email", "profile"),
					WithProviderCA(testCaPem),
					WithNow(testNow),
					WithProviderConfig(&ProviderConfig{
						AuthURL:     "https://auth-endpoint",
						JWKSURL:     "https://jwks-endpoint",
						TokenURL:    "https://token-endpoint",
						UserInfoURL: "https://userinfo-endpoint",
					}),
				},
			},
			want: &Config{
				Issuer:               "http://your_issuer/",
				ClientID:             "your_client_id",
				ClientSecret:         "your_client_secret",
				SupportedSigningAlgs: []Alg{RS512},
				Audiences:            []string{"your_aud1", "your_aud2"},
				Scopes:               []string{oidc.ScopeOpenID, "email", "profile"},
				ProviderCA:           testCaPem,
				NowFunc:              testNow,
				AllowedRedirectURLs: []string{
					"http://your_redirect_url",
					"http://redirect_url_two",
					"http://redirect_url_three",
				},
				ProviderConfig: &ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				},
			},
		},
		{
			name: "with-round-tripper",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url", "http://redirect_url_two", "http://redirect_url_three"},
				opt: []Option{
					WithAudiences("your_aud1", "your_aud2"),
					WithScopes("email", "profile"),
					WithRoundTripper(testRt),
					WithNow(testNow),
					WithProviderConfig(&ProviderConfig{
						AuthURL:     "https://auth-endpoint",
						JWKSURL:     "https://jwks-endpoint",
						TokenURL:    "https://token-endpoint",
						UserInfoURL: "https://userinfo-endpoint",
					}),
				},
			},
			want: &Config{
				Issuer:               "http://your_issuer/",
				ClientID:             "your_client_id",
				ClientSecret:         "your_client_secret",
				SupportedSigningAlgs: []Alg{RS512},
				Audiences:            []string{"your_aud1", "your_aud2"},
				Scopes:               []string{oidc.ScopeOpenID, "email", "profile"},
				RoundTripper:         testRt,
				NowFunc:              testNow,
				AllowedRedirectURLs: []string{
					"http://your_redirect_url",
					"http://redirect_url_two",
					"http://redirect_url_three",
				},
				ProviderConfig: &ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				},
			},
		},
		{
			name: "missing-provider-config-auth-url",
			args: args{
				issuer:       "http://your_issuer/",
				clientID:     "your_client_id",
				clientSecret: "your_client_secret",
				supported:    []Alg{RS512},
				opt: []Option{
					WithProviderConfig(&ProviderConfig{
						JWKSURL:     "https://jwks-endpoint",
						TokenURL:    "https://token-endpoint",
						UserInfoURL: "https://userinfo-endpoint",
					}),
				},
			},
			wantErr:         true,
			wantIsErr:       ErrInvalidParameter,
			wantErrContains: "missing AuthURL",
		},
		{
			name: "missing-provider-config-jwks-url",
			args: args{
				issuer:       "http://your_issuer/",
				clientID:     "your_client_id",
				clientSecret: "your_client_secret",
				supported:    []Alg{RS512},
				opt: []Option{
					WithProviderConfig(&ProviderConfig{
						AuthURL:     "https://auth-endpoint",
						TokenURL:    "https://token-endpoint",
						UserInfoURL: "https://userinfo-endpoint",
					}),
				},
			},
			wantErr:         true,
			wantIsErr:       ErrInvalidParameter,
			wantErrContains: "missing JWKSURL",
		},
		{
			name: "missing-provider-config-token-url",
			args: args{
				issuer:       "http://your_issuer/",
				clientID:     "your_client_id",
				clientSecret: "your_client_secret",
				supported:    []Alg{RS512},
				opt: []Option{
					WithProviderConfig(&ProviderConfig{
						AuthURL:     "https://auth-endpoint",
						JWKSURL:     "https://jwks-endpoint",
						UserInfoURL: "https://userinfo-endpoint",
					}),
				},
			},
			wantErr:         true,
			wantIsErr:       ErrInvalidParameter,
			wantErrContains: "missing TokenURL",
		},
		{
			name: "missing-provider-config-userinfo-url",
			args: args{
				issuer:       "http://your_issuer/",
				clientID:     "your_client_id",
				clientSecret: "your_client_secret",
				supported:    []Alg{RS512},
				opt: []Option{
					WithProviderConfig(&ProviderConfig{
						AuthURL:  "https://auth-endpoint",
						JWKSURL:  "https://jwks-endpoint",
						TokenURL: "https://token-endpoint",
					}),
				},
			},
			wantErr:         true,
			wantIsErr:       ErrInvalidParameter,
			wantErrContains: "missing UserInfoURL",
		},
		{
			name: "valid-empty-redirect",
			args: args{
				issuer:       "http://your_issuer/",
				clientID:     "your_client_id",
				clientSecret: "your_client_secret",
				supported:    []Alg{RS512},
			},
			want: &Config{
				Issuer:               "http://your_issuer/",
				ClientID:             "your_client_id",
				ClientSecret:         "your_client_secret",
				SupportedSigningAlgs: []Alg{RS512},
				Scopes:               []string{oidc.ScopeOpenID},
			},
		},
		{
			name: "invalid-redirects",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://a b.com/", "ht tp://foo.com"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-issuer",
			args: args{
				issuer:              "",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "bad-issuer-scheme",
			args: args{
				issuer:              "ldap://bad-scheme",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "bad-issuer-url",
			args: args{
				issuer:              "http://bad-url\\",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "empty-client-id",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-algs",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           nil,
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "invalid-providerCA",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
				opt: []Option{
					WithProviderCA("bad certificate"),
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidCACert,
		},
		{
			name: "invalid-both-cert-and-round-tripper",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{RS512},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
				opt: []Option{
					WithProviderCA(testCaPem),
					WithRoundTripper(testRt),
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "invalid-alg",
			args: args{
				issuer:              "http://your_issuer/",
				clientID:            "your_client_id",
				clientSecret:        "your_client_secret",
				supported:           []Alg{"bad alg"},
				allowedRedirectURLs: []string{"http://your_redirect_url"},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewConfig(tt.args.issuer, tt.args.clientID, tt.args.clientSecret, tt.args.supported, tt.args.allowedRedirectURLs, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(tt.want)
			assert.Equalf(tt.want.ClientID, got.ClientID, "ClientID = %v, want %v", got.ClientID, tt.want.ClientID)
			assert.Equalf(tt.want.ClientSecret, got.ClientSecret, "ClientSecret = %v, want %v", got.ClientSecret, tt.want.ClientSecret)
			assert.Equalf(tt.want.Scopes, got.Scopes, "Scopes = %v, want %v", got.Scopes, tt.want.Scopes)
			assert.Equalf(tt.want.Issuer, got.Issuer, "Issuer = %v, want %v", got.Issuer, tt.want.Issuer)
			assert.Equalf(tt.want.SupportedSigningAlgs, got.SupportedSigningAlgs, "SupportedSigningAlgs = %v, want %v", got.SupportedSigningAlgs, tt.want.SupportedSigningAlgs)
			assert.Equalf(tt.want.Audiences, got.Audiences, "Audiences = %v, want %v", got.Audiences, tt.want.Audiences)
			assert.Equalf(tt.want.ProviderCA, got.ProviderCA, "ProviderCA = %v, want %v", got.ProviderCA, tt.want.ProviderCA)
			testAssertEqualFunc(t, tt.want.NowFunc, got.NowFunc, "NowFunc = %p,want %p", tt.want.NowFunc, got.NowFunc)
			assert.Equalf(tt.want.AllowedRedirectURLs, got.AllowedRedirectURLs, "AllowedRedirectURLs = %v, want %v", got.AllowedRedirectURLs, tt.want.AllowedRedirectURLs)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	// Validate testing is covered by TestNewConfig() but we do have just one
	// more test to add here.
	t.Parallel()
	t.Run("nil-config", func(t *testing.T) {
		assert := assert.New(t)
		var c *Config
		err := c.Validate()
		assert.Truef(errors.Is(err, ErrNilParameter), "Config.Validate() = %v, want %v", err, ErrNilParameter)
	})
}

func Test_WithProviderCA(t *testing.T) {
	t.Parallel()
	_, testCaPem := TestGenerateCA(t, []string{"localhost"})
	assert := assert.New(t)
	opts := getConfigOpts(WithProviderCA(testCaPem))
	testOpts := configDefaults()
	testOpts.withProviderCA = testCaPem
	assert.Equal(opts, testOpts)
}

func TestConfig_Now(t *testing.T) {
	tests := []struct {
		name    string
		nowFunc func() time.Time
		want    func() time.Time
		skew    time.Duration
	}{
		{
			name:    "default-time",
			nowFunc: nil,
			want:    time.Now,
			skew:    1 * time.Millisecond,
		},
		{
			name:    "time-travel-backward",
			nowFunc: func() time.Time { return time.Now().Add(-10 * time.Millisecond) },
			want:    func() time.Time { return time.Now().Add(-10 * time.Millisecond) },
			skew:    1 * time.Millisecond,
		},
		{
			name:    "time-travel-forward",
			nowFunc: func() time.Time { return time.Now().Add(10 * time.Millisecond) },
			want:    func() time.Time { return time.Now().Add(10 * time.Millisecond) },
			skew:    1 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			c := &Config{NowFunc: tt.nowFunc}
			assert.True(c.Now().Before(tt.want()))
			assert.True(c.Now().Add(tt.skew).After(tt.want()))
		})
	}
}

func TestEncodeCertificates(t *testing.T) {
	testCert, testPem := TestGenerateCA(t, []string{"localhost"})

	tests := []struct {
		name      string
		certs     []*x509.Certificate
		want      string
		wantErr   bool
		wantIsErr error
	}{
		{
			name:  "valid",
			certs: []*x509.Certificate{testCert, testCert},
			want:  testPem + testPem,
		},
		{
			name:      "no-certs",
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name:      "nil-cert",
			certs:     []*x509.Certificate{testCert, nil},
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := EncodeCertificates(tt.certs...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			if got != tt.want {
				t.Errorf("EncodeCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Hash(t *testing.T) {
	_, pem := TestGenerateCA(t, []string{"localhost"})
	newCfg := func(issuer string, clientID string, clientSecret ClientSecret, supported []Alg, allowedRedirectURLs []string, opt ...Option) *Config {
		c, err := NewConfig(issuer, clientID, clientSecret, supported, allowedRedirectURLs, opt...)
		require.NoError(t, err)
		return c
	}
	testRt := newTestRoundTripper(t)
	tests := []struct {
		name      string
		c1        *Config
		c2        *Config
		wantEqual bool
		wantErr   bool
	}{
		{
			name: "equal",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback", "www.bob.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.bob.com/callback", "www.alice.com/callback"},
				WithScopes("profile", "email"),
				WithAudiences("bob.com", "alice.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: true,
		},
		{
			name: "equal-with-round-tripper",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback", "www.bob.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithRoundTripper(testRt),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.bob.com/callback", "www.alice.com/callback"},
				WithScopes("profile", "email"),
				WithAudiences("bob.com", "alice.com"),
				WithRoundTripper(testRt),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: true,
		},
		{
			name: "diff-issuer",
			c1: newCfg(
				"https://www.bob.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-client-id",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"diff-client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-secret",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-not-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-alg",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256, RS384},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-redirects",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.bob.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-scope",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-aud",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-CA",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-round-trippers",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithRoundTripper(newTestRoundTripper(t)),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithNow(time.Now),
			),
			wantEqual: false,
		},
		{
			name: "diff-now-func",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(func() time.Time {
					return time.Now().Add(-1 * time.Minute)
				}),
			),
			wantEqual: false,
		},
		{
			name: "diff-provider-config-auth-url",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://diff-auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: false,
		},
		{
			name: "diff-provider-config-jwks-url",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://diff-jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: false,
		},
		{
			name: "diff-provider-config-token-url",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://diff-token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: false,
		},
		{
			name: "diff-provider-config-userinfo-url",
			c1: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://diff-userinfo-endpoint",
				}),
			),
			c2: newCfg(
				"https://www.alice.com",
				"client-id", "client-secret",
				[]Alg{RS256},
				[]string{"www.alice.com/callback"},
				WithScopes("email", "profile"),
				WithAudiences("alice.com", "bob.com"),
				WithProviderCA(pem),
				WithNow(time.Now),
				WithProviderConfig(&ProviderConfig{
					AuthURL:     "https://auth-endpoint",
					JWKSURL:     "https://jwks-endpoint",
					TokenURL:    "https://token-endpoint",
					UserInfoURL: "https://userinfo-endpoint",
				}),
			),
			wantEqual: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got1, err := tt.c1.Hash()
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			got2, err := tt.c2.Hash()
			require.NoError(err)
			switch tt.wantEqual {
			case true:
				assert.Equal(got1, got2)
			default:
				assert.NotEqual(got1, got2)
			}
		})
	}
}

type testRoundTripper struct {
	transport http.RoundTripper
	called    int
}

func newTestRoundTripper(t *testing.T) *testRoundTripper {
	t.Helper()
	return &testRoundTripper{
		transport: http.DefaultTransport,
	}
}

func (rt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.called++
	return rt.transport.RoundTrip(req)
}
