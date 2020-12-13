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
	tests := []struct {
		name            string
		expireIn        time.Duration
		opts            []Option
		wantNowFunc     func() time.Time
		wantRedirectURL string
		wantAudiences   []string
		wantScopes      []string
		wantErr         bool
		wantIsErr       error
	}{
		{
			name:     "valid-with-all-options",
			expireIn: defaultExpireIn,
			opts: []Option{
				WithNow(testNow),
				WithRedirectURL("https://bobs.com"),
				WithAudiences("bob", "alice"),
				WithScopes("email", "profile"),
			},
			wantNowFunc:     testNow,
			wantRedirectURL: "https://bobs.com",
			wantAudiences:   []string{"bob", "alice"},
			wantScopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		},
		{
			name:     "valid-no-opt",
			expireIn: defaultExpireIn,
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
			got, err := NewState(tt.expireIn, tt.opts...)
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
		})
	}
}

func TestState_IsExpired(t *testing.T) {
	t.Parallel()
	t.Run("not-expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewState(2 * time.Second)
		require.NoError(err)
		assert.False(s.IsExpired())
	})
	t.Run("expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := NewState(1 * time.Nanosecond)
		require.NoError(err)
		assert.True(s.IsExpired())
	})

}
