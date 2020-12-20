package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewState(t *testing.T) {
	t.Parallel()
	skew := 250 * time.Millisecond
	defaultExpireIn := 1 * time.Second
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}

	testVerifier, err := NewCodeVerifier()
	require.NoError(t, err)

	tests := []struct {
		name            string
		expireIn        time.Duration
		redirectURL     string
		opts            []Option
		wantNowFunc     func() time.Time
		wantRedirectURL string
		wantAudiences   []string
		wantScopes      []string
		wantVerifier    CodeVerifier
		wantErr         bool
		wantIsErr       error
	}{
		{
			name:        "valid-with-all-options",
			expireIn:    defaultExpireIn,
			redirectURL: "https://bob.com",
			opts: []Option{
				WithNow(testNow),
				WithAudiences("bob", "alice"),
				WithScopes("email", "profile"),
				WithPKCE(testVerifier),
			},
			wantNowFunc:     testNow,
			wantRedirectURL: "https://bob.com",
			wantAudiences:   []string{"bob", "alice"},
			wantScopes:      []string{oidc.ScopeOpenID, "email", "profile"},
			wantVerifier:    testVerifier,
		},
		{
			name:            "valid-no-opt",
			expireIn:        defaultExpireIn,
			redirectURL:     "https://bob.com",
			wantRedirectURL: "https://bob.com",
		},
		{
			name:      "zero-expireIn",
			expireIn:  0,
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewState(tt.expireIn, tt.redirectURL, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			tExp := got.now().Add(tt.expireIn)
			assert.True(got.expiration.Before(tExp.Add(skew)))
			assert.True(got.expiration.After(tExp.Add(-skew)))
			assert.NotEqualf(got.ID(), got.Nonce(), "%s id should not equal %s nonce", got.ID(), got.Nonce())
			assert.NotEmpty(got.ID())
			assert.NotEmpty(got.Nonce())
			testAssertEqualFunc(t, tt.wantNowFunc, got.nowFunc, "now = %p,want %p", tt.wantNowFunc, got.nowFunc)
			assert.Equalf(got.RedirectURL(), tt.wantRedirectURL, "wanted \"%s\" but got \"%s\"", tt.wantRedirectURL, got.RedirectURL())
			assert.Equalf(got.Audiences(), tt.wantAudiences, "wanted \"%s\" but got \"%s\"", tt.wantAudiences, got.Audiences())
			assert.Equalf(got.Scopes(), tt.wantScopes, "wanted \"%s\" but got \"%s\"", tt.wantScopes, got.Scopes())
			assert.Equalf(got.PKCEVerifier(), tt.wantVerifier, "wanted \"%s\" but got \"%s\"", tt.wantVerifier, got.PKCEVerifier())
		})
	}
}

func TestState_IsExpired(t *testing.T) {
	t.Parallel()
	t.Run("not-expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewState(2*time.Second, "https://redirect")
		require.NoError(err)
		assert.False(s.IsExpired())
	})
	t.Run("expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewState(1*time.Nanosecond, "https://redirect")
		require.NoError(err)
		assert.True(s.IsExpired())
	})

}

func Test_WithImplicit(t *testing.T) {
	t.Parallel()
	t.Run("stOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getStOpts()
		testOpts := stDefaults()
		assert.Equal(opts, testOpts)

		opts = getStOpts(WithImplicitFlow())
		testOpts = stDefaults()
		testOpts.withImplicitFlow = &implicitFlow{}
		assert.Equal(opts, testOpts)

		opts = getStOpts(WithImplicitFlow(true))
		testOpts = stDefaults()
		testOpts.withImplicitFlow = &implicitFlow{true}
		assert.Equal(opts, testOpts)
	})
}

func Test_WithPKCE(t *testing.T) {
	t.Parallel()
	t.Run("stOptions", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		opts := getStOpts()
		testOpts := stDefaults()
		assert.Equal(opts, testOpts)
		assert.Nil(testOpts.withVerifier)

		v, err := NewCodeVerifier()
		require.NoError(err)
		opts = getStOpts(WithPKCE(v))
		testOpts = stDefaults()
		testOpts.withVerifier = v
		assert.Equal(opts, testOpts)
	})
}
