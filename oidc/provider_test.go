package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestWithImplicitFlow(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getProviderOpts(WithImplicitFlow())
	testOpts := providerDefaults()
	testOpts.withImplicitFlow = &implicitFlow{withoutAccessToken: false}
	assert.Equal(opts, testOpts)

	opts = getProviderOpts(WithImplicitFlow(true))
	testOpts = providerDefaults()
	testOpts.withImplicitFlow = &implicitFlow{withoutAccessToken: true}
	assert.Equal(opts, testOpts)
}

// TestNewProvider does not repeat all the Config unit tests.  It just focuses
// on the additional tests that are unique to creating a new provider.
func TestNewProvider(t *testing.T) {
	t.Parallel()
	tp := StartTestProvider(t)
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	redirect := "test-redirect"
	tests := []struct {
		name      string
		config    *Config
		wantErr   bool
		wantIsErr error
	}{
		{
			name:   "valid",
			config: testNewConfig(t, clientID, clientSecret, redirect, tp),
		},
		{
			name:      "nil-config",
			config:    nil,
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "invalid-config",
			config: func() *Config {
				c := testNewConfig(t, clientID, clientSecret, redirect, tp)
				c.Issuer = ""
				return c
			}(),
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewProvider(tt.config)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.NotNil(got.config)
			assert.NotNil(got.provider)
			assert.NotNil(got.client)
			assert.NotNil(got.backgroundCtx)
			assert.NotNil(got.backgroundCtxCancel)
		})
	}
}

func TestProvider_Done(t *testing.T) {
	t.Parallel()
	tp := StartTestProvider(t)
	p := testNewProvider(t, "client-id", "client-secret", "redirect", tp)

	tests := []struct {
		name                string
		provider            *oidc.Provider
		client              *http.Client
		backgroundCtx       context.Context
		backgroundCtxCancel context.CancelFunc
	}{
		{
			name:                "all-valid",
			provider:            p.provider,
			client:              p.client,
			backgroundCtx:       p.backgroundCtx,
			backgroundCtxCancel: p.backgroundCtxCancel,
		},
		{
			name:                "nil-provider",
			provider:            nil,
			client:              p.client,
			backgroundCtx:       p.backgroundCtx,
			backgroundCtxCancel: p.backgroundCtxCancel,
		},
		{
			name:                "nil-client",
			provider:            p.provider,
			client:              nil,
			backgroundCtx:       p.backgroundCtx,
			backgroundCtxCancel: p.backgroundCtxCancel,
		},
		{
			name:                "nil-backgroundCtx",
			provider:            p.provider,
			client:              p.client,
			backgroundCtx:       p.backgroundCtx,
			backgroundCtxCancel: nil,
		},
		{
			name:                "nil-backgroundCtxCancel",
			provider:            p.provider,
			client:              p.client,
			backgroundCtx:       p.backgroundCtx,
			backgroundCtxCancel: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				provider:            tt.provider,
				client:              tt.client,
				backgroundCtx:       tt.backgroundCtx,
				backgroundCtxCancel: tt.backgroundCtxCancel,
			}
			p.Done()
		})
	}
	t.Run("nil-provider", func(t *testing.T) {
		var p *Provider
		p.Done()
	})
}

func TestProvider_AuthURL(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	redirect := "test-redirect"
	tp := StartTestProvider(t)
	p := testNewProvider(t, clientID, clientSecret, redirect, tp)
	validState, err := NewState(1 * time.Second)
	require.NoError(t, err)

	allOptsState, err := NewState(
		1*time.Second,
		WithRedirectURL("https://state-override"),
		WithAudiences("state-override"),
		WithScopes("email", "profile"),
	)
	require.NoError(t, err)

	type args struct {
		ctx context.Context
		s   State
		opt []Option
	}
	tests := []struct {
		name      string
		p         *Provider
		args      args
		wantURL   string
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-using-default-auth-flow",
			p:    p,
			args: args{
				ctx: ctx,
				s:   validState,
			},
			wantURL: func() string {
				return fmt.Sprintf(
					"%s/authorize?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s",
					tp.Addr(),
					clientID,
					validState.Nonce(),
					redirect,
					validState.ID(),
				)
			}(),
		},
		{
			name: "valid-using-implicit-flow",
			p:    p,
			args: args{
				ctx: ctx,
				s:   validState,
				opt: []Option{WithImplicitFlow()},
			},
			wantURL: func() string {
				return fmt.Sprintf(
					"%s/authorize?client_id=%s&nonce=%s&redirect_uri=%s&response_mode=form_post&response_type=id_token+token&scope=openid&state=%s",
					tp.Addr(),
					clientID,
					validState.Nonce(),
					redirect,
					validState.ID(),
				)
			}(),
		},
		{
			name: "valid-with-all-options-state",
			p:    p,
			args: args{
				ctx: ctx,
				s:   allOptsState,
			},
			wantURL: func() string {
				return fmt.Sprintf(
					"%s/authorize?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
					tp.Addr(),
					clientID,
					allOptsState.Nonce(),
					"https%3A%2F%2Fstate-override",
					allOptsState.ID(),
				)
			}(),
		},
		{
			name: "valid-using-implicit-flow-no-access-token",
			p:    p,
			args: args{
				ctx: ctx,
				s:   validState,
				opt: []Option{WithImplicitFlow(true)},
			},
			wantURL: func() string {
				return fmt.Sprintf(
					"%s/authorize?client_id=%s&nonce=%s&redirect_uri=%s&response_mode=form_post&response_type=id_token&scope=openid&state=%s",
					tp.Addr(),
					clientID,
					validState.Nonce(),
					redirect,
					validState.ID(),
				)
			}(),
		},
		{
			name: "empty-state-nonce",
			p:    p,
			args: args{
				ctx: ctx,
				s: &St{
					id: "s_1234567890",
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-state-id",
			p:    p,
			args: args{
				ctx: ctx,
				s: &St{
					nonce: "s_1234567890",
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "equal-state-id-and-nonce",
			p:    p,
			args: args{
				ctx: ctx,
				s: &St{
					id:    "s_1234567890",
					nonce: "s_1234567890",
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotURL, err := tt.p.AuthURL(tt.args.ctx, tt.args.s, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.Equalf(tt.wantURL, gotURL, "Provider.AuthURL() = %v, want %v", gotURL, tt.wantURL)
		})
	}
}

func TestProvider_Exchange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	redirect := "https://test-redirect"

	tp := StartTestProvider(t)
	tp.SetAllowedRedirectURIs([]string{redirect, "https://state-override"})
	p := testNewProvider(t, clientID, clientSecret, redirect, tp)

	validState, err := NewState(10 * time.Second)
	require.NoError(t, err)

	expiredState, err := NewState(1 * time.Nanosecond)
	require.NoError(t, err)

	allOptsState, err := NewState(
		10*time.Second,
		WithRedirectURL("https://state-override"),
		WithAudiences("state-override"),
		WithScopes("email", "profile"),
	)
	require.NoError(t, err)

	type args struct {
		ctx               context.Context
		s                 State
		authState         string
		authCode          string
		expectedNonce     string
		expectedAudiences []string
	}
	tests := []struct {
		name      string
		p         *Provider
		args      args
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid",
			p:    p,
			args: args{
				ctx:       ctx,
				s:         validState,
				authState: validState.ID(),
				authCode:  "test-code",
			},
		},
		{
			name: "valid-all-opts-state",
			p:    p,
			args: args{
				ctx:               ctx,
				s:                 allOptsState,
				authState:         allOptsState.ID(),
				authCode:          "test-code",
				expectedAudiences: []string{"state-override"},
			},
		},
		{
			name:      "nil-config",
			p:         &Provider{},
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "states-don't-match",
			p:    p,
			args: args{
				ctx:       ctx,
				s:         validState,
				authState: "not-equal",
				authCode:  "test-code",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "expired-state",
			p:    p,
			args: args{
				ctx:       ctx,
				s:         expiredState,
				authState: expiredState.ID(),
				authCode:  "test-code",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tp.SetExpectedAuthCode(tt.args.authCode)

			// default to the state's nonce...
			if tt.args.s != nil {
				tp.SetExpectedAuthNonce(tt.args.s.Nonce())
			}
			if tt.args.expectedNonce != "" {
				tp.SetExpectedAuthNonce(tt.args.expectedNonce)
			}
			if len(tt.args.expectedAudiences) != 0 {
				tp.SetCustomAudience(tt.args.expectedAudiences...)
				tp.SetCustomClaims(map[string]interface{}{"azp": clientID})
			}
			gotTk, err := tt.p.Exchange(tt.args.ctx, tt.args.s, tt.args.authState, tt.args.authCode)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			require.NotEmptyf(gotTk, "Provider.Exchange() = %v, wanted not nil", gotTk)
			assert.NotEmptyf(gotTk.IDToken(), "gotTk.IDToken() = %v, wanted not empty", gotTk.IDToken())
			assert.NotEmptyf(gotTk.AccessToken(), "gotTk.AccessToken() = %v, wanted not empty", gotTk.AccessToken())
			assert.Truef(gotTk.Valid(), "gotTk.Valid() = %v, wanted true", gotTk.Valid())
			assert.Truef(!gotTk.IsExpired(), "gotTk.Expired() = %v, wanted false", gotTk.IsExpired())
		})
	}

	t.Run("bad-expected-auth-code", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		code := "code-doesn't-match-state"
		tp.SetExpectedAuthCode(code)
		gotTk, err := p.Exchange(ctx, validState, validState.ID(), "bad-code")
		require.Error(err)
		assert.Truef(strings.Contains(err.Error(), "401 Unauthorized"), "wanted strings.Contains \"%s\" but got \"%s\"", "401 Unauthorized", err)
		assert.Empty(gotTk)
	})
	t.Run("omit-id-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp.SetOmitIDTokens(true)
		tp.SetExpectedAuthCode("valid-code")
		gotTk, err := p.Exchange(ctx, validState, validState.ID(), "valid-code")
		require.Error(err)
		assert.Truef(errors.Is(err, ErrMissingIDToken), "wanted \"%s\" but got \"%s\"", ErrMissingIDToken, err)
		assert.Empty(gotTk)
	})
	t.Run("omit-access-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp.SetOmitAccessTokens(true)
		defer tp.SetOmitAccessTokens(false)
		tp.SetExpectedAuthCode("valid-code")
		gotTk, err := p.Exchange(ctx, validState, validState.ID(), "valid-code")
		require.Error(err)
		assert.Nil(gotTk)
		assert.Truef(errors.Is(err, ErrMissingAccessToken), "wanted \"%s\" but got \"%s\"", ErrMissingAccessToken, err)
	})
	t.Run("expired-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tp.SetOmitIDTokens(false)
		tp.SetExpectedAuthCode("valid-code")
		tp.SetExpectedExpiry(-1 * time.Minute)
		gotTk, err := p.Exchange(ctx, validState, validState.ID(), "valid-code")
		require.Error(err)
		assert.Truef(errors.Is(err, ErrExpiredToken), "wanted \"%s\" but got \"%s\"", ErrExpiredToken, err)
		assert.Empty(gotTk)
	})
}

func TestHttpClient(t *testing.T) {
	// HttpClientContext if mostly covered by other tests, but we need to make
	// sure we handle nil configs and invalid CA certs
	t.Parallel()
	t.Run("nil-config", func(t *testing.T) {
		p := &Provider{}
		c, err := p.HttpClient()
		assert.Error(t, err)
		assert.Truef(t, errors.Is(err, ErrNilParameter), "wanted \"%s\" but got \"%s\"", ErrNilParameter, err)
		assert.Empty(t, c)
	})
	t.Run("bad-cert", func(t *testing.T) {
		p := &Provider{
			config: &Config{
				ProviderCA: "bad-cert",
			},
		}
		c, err := p.HttpClient()
		require.Error(t, err)
		assert.Truef(t, errors.Is(err, ErrInvalidCACert), "wanted \"%s\" but got \"%s\"", ErrInvalidCACert, err)
		assert.Empty(t, c)
	})
}

func TestProvider_UserInfo(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	redirect := "test-redirect"

	tp := StartTestProvider(t)
	tp.SetAllowedRedirectURIs([]string{redirect})
	p := testNewProvider(t, clientID, clientSecret, redirect, tp)

	type args struct {
		tokenSource oauth2.TokenSource
		claims      interface{}
	}
	tests := []struct {
		name       string
		p          *Provider
		args       args
		wantClaims interface{}
		wantErr    bool
		wantIsErr  error
	}{
		{
			name: "valid",
			p:    p,
			args: args{
				tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: "dummy_access_token",
					Expiry:      time.Now().Add(10 * time.Second),
				}),
				claims: &map[string]interface{}{},
			},
			wantClaims: &map[string]interface{}{
				"advisor":       "Faythe",
				"dob":           "1978",
				"friend":        "bob",
				"nickname":      "A",
				"nosy-neighbor": "Eve",
			},
		},
		{
			name: "nil-tokensource",
			p:    p,
			args: args{
				tokenSource: nil,
				claims:      &map[string]interface{}{},
			},
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "nil-claims",
			p:    p,
			args: args{
				tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: "dummy_access_token",
					Expiry:      time.Now().Add(10 * time.Second),
				}),
				claims: nil,
			},
			wantErr:   true,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "non-ptr-claims",
			p:    p,
			args: args{
				tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: "dummy_access_token",
					Expiry:      time.Now().Add(10 * time.Second),
				}),
				claims: map[string]interface{}{},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := p.UserInfo(ctx, tt.args.tokenSource, tt.args.claims)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			require.NotEmptyf(tt.args.claims, "expected claims to not be empty")
			require.Equalf(tt.wantClaims, tt.args.claims, "wanted \"%s\" but got \"%s\"", tt.wantClaims, tt.args.claims)
		})
	}
	t.Run("failed-request", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "dummy_access_token",
			Expiry:      time.Now().Add(10 * time.Second),
		})
		tp.DisableUserInfo()
		var claims interface{}
		err := p.UserInfo(ctx, tokenSource, &claims)
		require.Error(err)
		assert.Empty(claims)
	})
}

func TestProvider_VerifyIDToken(t *testing.T) {
	type keys struct {
		priv  crypto.PrivateKey
		pub   crypto.PublicKey
		alg   Alg
		keyID string
	}
	ctx := context.Background()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	redirect := "test-redirect"
	tp := StartTestProvider(t)
	tp.SetAllowedRedirectURIs([]string{redirect})
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	defaultKeys := keys{priv: k, pub: &k.PublicKey, alg: ES256, keyID: "valid-ES256"}
	defaultValidNonce := "valid"
	defaultClaims :=
		map[string]interface{}{
			"sub":   "alice@bob.com",
			"aud":   []string{clientID},
			"nbf":   float64(time.Now().Unix()),
			"iat":   float64(time.Now().Unix()),
			"exp":   float64(time.Now().Add(1 * time.Minute).Unix()),
			"id":    "1",
			"nonce": defaultValidNonce,
		}
	type args struct {
		keys           keys
		claims         map[string]interface{}
		nonce          string
		overrideIssuer string
		opt            []Option
	}
	tests := []struct {
		name      string
		p         *Provider
		args      args
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-ES256",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES256}
				return p
			}(),
			args: args{
				keys:   defaultKeys,
				claims: defaultClaims,
				nonce:  defaultValidNonce,
			},
		},
		{
			name: "nonces-not-equal",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES256}
				return p
			}(),
			args: args{
				keys:   defaultKeys,
				claims: defaultClaims,
				nonce:  "not-valid",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidNonce,
		},
		{
			name: "valid-with-audiences-option",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES256}
				return p
			}(),
			args: args{
				keys:   defaultKeys,
				claims: defaultClaims,
				nonce:  defaultValidNonce,
				opt:    []Option{WithAudiences(clientID, "second-aud")},
			},
		},
		{
			name: "unsupported-alg",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{RS256}
				return p
			}(),
			args: args{
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: defaultClaims,
				nonce:  defaultValidNonce,
			},
			wantErr:   true,
			wantIsErr: ErrUnsupportedAlg,
		},
		{
			name: "bad-issuer",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES384}
				return p
			}(),
			args: args{
				overrideIssuer: "bad-issuer",
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: defaultClaims,
				nonce:  defaultValidNonce,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "bad-nbf",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES384}
				return p
			}(),
			args: args{
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: func() map[string]interface{} {
					c := map[string]interface{}{
						"sub":   "alice@bob.com",
						"aud":   []string{clientID},
						"nbf":   float64(time.Now().Add(10 * time.Minute).Unix()),
						"iat":   float64(time.Now().Unix()),
						"exp":   float64(time.Now().Add(1 * time.Minute).Unix()),
						"id":    "1",
						"nonce": defaultValidNonce,
					}
					return c
				}(),
				nonce: defaultValidNonce,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidNotBefore,
		},
		{
			name: "bad-exp",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES384}
				return p
			}(),
			args: args{
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: func() map[string]interface{} {
					c := map[string]interface{}{
						"sub":   "alice@bob.com",
						"aud":   []string{clientID},
						"nbf":   float64(time.Now().Unix()),
						"iat":   float64(time.Now().Unix()),
						"exp":   float64(time.Now().Add(-10 * time.Minute).Unix()),
						"id":    "1",
						"nonce": defaultValidNonce,
					}
					return c
				}(),
				nonce: defaultValidNonce,
			},
			wantErr:   true,
			wantIsErr: ErrExpiredToken,
		},
		{
			name: "bad-iat",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES384}
				return p
			}(),
			args: args{
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: func() map[string]interface{} {
					c := map[string]interface{}{
						"sub":   "alice@bob.com",
						"aud":   []string{clientID},
						"nbf":   float64(time.Now().Unix()),
						"iat":   float64(time.Now().Add(10 * time.Minute).Unix()),
						"exp":   float64(time.Now().Add(1 * time.Minute).Unix()),
						"id":    "1",
						"nonce": defaultValidNonce,
					}
					return c
				}(),
				nonce: defaultValidNonce,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuedAt,
		},
		{
			name: "valid-ES384",
			p: func() *Provider {
				p := testNewProvider(t, clientID, clientSecret, redirect, tp)
				p.config.SupportedSigningAlgs = []Alg{ES384}
				return p
			}(),
			args: args{
				keys: func() keys {
					k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					require.NoError(t, err)
					return keys{priv: k, pub: &k.PublicKey, alg: ES384, keyID: "valid-ES384"}
				}(),
				claims: defaultClaims,
				nonce:  defaultValidNonce,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tp.SetSigningKeys(tt.args.keys.priv, tt.args.keys.pub, tt.args.keys.alg, tt.args.keys.keyID)
			priv, pub, alg := tp.SigningKeys()
			require.Equalf(tt.args.keys.priv, priv, "TestProvider priv key is invalid")
			require.Equalf(tt.args.keys.pub, pub, "TestProvider pub key is invalid")
			require.Equalf(tt.args.keys.alg, alg, "TestProvider alg key is invalid")
			switch {
			case tt.args.overrideIssuer != "":
				tt.args.claims["iss"] = tt.args.overrideIssuer
			default:
				tt.args.claims["iss"] = tt.p.config.Issuer
			}
			idToken := IDToken(TestSignJWT(t, tt.args.keys.priv, tt.args.keys.alg, tt.args.claims, []byte(tt.args.keys.keyID)))
			err := tt.p.VerifyIDToken(ctx, idToken, tt.args.nonce, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantIsErr != nil {
					assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				}
				return
			}
			require.NoError(err)
		})
	}
	t.Run("bad-sig", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		p := testNewProvider(t, clientID, clientSecret, redirect, tp)
		p.config.SupportedSigningAlgs = []Alg{defaultKeys.alg}
		tp.SetSigningKeys(defaultKeys.priv, defaultKeys.pub, defaultKeys.alg, defaultKeys.keyID)
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(err)
		defaultClaims["iss"] = p.config.Issuer
		idToken := IDToken(TestSignJWT(t, k, ES256, defaultClaims, []byte(defaultKeys.keyID)))
		err = p.VerifyIDToken(ctx, idToken, "valid")
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidSignature), "wanted \"%s\" but got \"%s\"", ErrInvalidSignature, err)
	})
	t.Run("empty-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		p := testNewProvider(t, clientID, clientSecret, redirect, tp)
		p.config.SupportedSigningAlgs = []Alg{ES256}
		err := p.VerifyIDToken(ctx, "", "nonce")
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidParameter), "wanted \"%s\" but got \"%s\"", ErrInvalidParameter, err)
	})
	t.Run("empty-nonce", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		p := testNewProvider(t, clientID, clientSecret, redirect, tp)
		p.config.SupportedSigningAlgs = []Alg{ES256}
		err := p.VerifyIDToken(ctx, "token", "")
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidParameter), "wanted \"%s\" but got \"%s\"", ErrInvalidParameter, err)
	})
	t.Run("missing-and-disabled-jwks", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		p := testNewProvider(t, clientID, clientSecret, redirect, tp)
		p.config.SupportedSigningAlgs = []Alg{defaultKeys.alg}
		tp.SetSigningKeys(defaultKeys.priv, defaultKeys.pub, defaultKeys.alg, defaultKeys.keyID)
		claims := map[string]interface{}{
			"sub":   "alice@bob.com",
			"aud":   []string{clientID},
			"nbf":   float64(time.Now().Unix()),
			"iat":   float64(time.Now().Unix()),
			"exp":   float64(time.Now().Add(1 * time.Minute).Unix()),
			"id":    "1",
			"nonce": defaultValidNonce,
			"iss":   p.config.Issuer,
		}
		idToken := IDToken(TestSignJWT(t, defaultKeys.priv, defaultKeys.alg, claims, []byte(defaultKeys.keyID)))
		func() {
			tp.SetDisableJWKs(true)
			defer tp.SetDisableJWKs(false)
			err := p.VerifyIDToken(ctx, idToken, "valid")
			require.Error(err)
			assert.Truef(errors.Is(err, ErrInvalidJWKs), "wanted \"%s\" but got \"%s\"", ErrInvalidJWKs, err)
		}()
		idToken = IDToken(TestSignJWT(t, defaultKeys.priv, defaultKeys.alg, claims, []byte(defaultKeys.keyID)))
		func() {
			tp.SetInvalidJWKS(true)
			defer tp.SetInvalidJWKS(false)
			err = p.VerifyIDToken(ctx, idToken, "valid")
			require.Error(err)
			assert.Truef(errors.Is(err, ErrInvalidJWKs), "wanted \"%s\" but got \"%s\"", ErrInvalidJWKs, err)
		}()
	})
}
