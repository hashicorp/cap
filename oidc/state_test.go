package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewState(t *testing.T) {
	t.Parallel()
	skew := 1 * time.Millisecond
	defaultExpireIn := 500 * time.Millisecond
	tests := []struct {
		name          string
		expireIn      time.Duration
		wantExpAfter  time.Time
		wantExpBefore time.Time
		wantErr       bool
		wantIsErr     error
	}{
		{
			name:          "valid",
			expireIn:      defaultExpireIn,
			wantExpAfter:  time.Now().Add(defaultExpireIn),
			wantExpBefore: time.Now().Add(defaultExpireIn + skew),
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
			got, err := NewState(tt.expireIn)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.True(got.expiration.Before(tt.wantExpBefore))
			assert.True(got.expiration.After(tt.wantExpAfter))
			assert.NotEqualf(got.ID(), got.Nonce(), "%s id should not equal %s nonce", got.ID(), got.Nonce())
			assert.NotEmpty(got.ID())
			assert.NotEmpty(got.Nonce())
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
