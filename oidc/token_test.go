// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewToken(t *testing.T) {
	t.Parallel()
	_, priv := TestGenerateKeys(t)
	testJWT := testDefaultJWT(t, priv, 1*time.Minute, "123456789", nil)
	testAccessToken := "test_access_token"
	testRefreshToken := "test_refresh_token"
	testExpiry := time.Now().Add(1 * time.Minute)
	testUnderlying := &oauth2.Token{
		AccessToken:  testAccessToken,
		RefreshToken: testRefreshToken,
		Expiry:       testExpiry,
	}

	testUnderlyingZeroExpiry := &oauth2.Token{
		AccessToken:  testAccessToken,
		RefreshToken: testRefreshToken,
	}
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}

	tests := []struct {
		name             string
		idToken          IDToken
		oauthToken       *oauth2.Token
		opts             []Option
		want             *Tk
		wantNowFunc      func() time.Time
		wantIDToken      IDToken
		wantAccessToken  AccessToken
		wantRefreshToken RefreshToken
		wantTokenSource  oauth2.TokenSource
		wantExpiry       time.Time
		wantExpired      bool
		wantValid        bool
		wantErr          bool
		wantIsErr        error
	}{
		{
			name:       "valid",
			idToken:    IDToken(testJWT),
			oauthToken: testUnderlying,
			opts:       []Option{WithNow(testNow)},
			want: &Tk{
				idToken:          IDToken(testJWT),
				underlying:       testUnderlying,
				nowFunc:          testNow,
				additionalClaims: map[string]any{},
			},
			wantIDToken:      IDToken(testJWT),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlying),
			wantExpiry:       testExpiry,
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:       "valid-def-now-func",
			idToken:    IDToken(testJWT),
			oauthToken: testUnderlying,
			opts:       []Option{},
			want: &Tk{
				idToken:          IDToken(testJWT),
				underlying:       testUnderlying,
				additionalClaims: map[string]any{},
			},
			wantIDToken:      IDToken(testJWT),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlying),
			wantExpiry:       testExpiry,
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:    "valid-without-accessToken",
			idToken: IDToken(testJWT),
			want: &Tk{
				idToken:          IDToken(testJWT),
				additionalClaims: map[string]any{},
			},
			wantIDToken: IDToken(testJWT),
			wantExpired: true,
			wantValid:   false,
		},
		{
			name:       "valid-with-accessToken-and-zero-expiry",
			idToken:    IDToken(testJWT),
			oauthToken: testUnderlyingZeroExpiry,
			want: &Tk{
				idToken:          IDToken(testJWT),
				underlying:       testUnderlyingZeroExpiry,
				additionalClaims: map[string]any{},
			},
			wantIDToken:      IDToken(testJWT),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlyingZeroExpiry),
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:    "empty-idToken",
			idToken: IDToken(""),
			oauthToken: &oauth2.Token{
				AccessToken: testAccessToken,
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewToken(tt.idToken, tt.oauthToken, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.Equalf(tt.want.underlying, got.underlying, "NewToken() = %v, want %v", got.underlying, tt.want.underlying)
			assert.Equalf(tt.wantIDToken, got.IDToken(), "t.IDToken() = %v, want %v", tt.wantIDToken, got.IDToken())
			assert.Equalf(tt.wantAccessToken, got.AccessToken(), "t.AccessToken() = %v, want %v", tt.wantAccessToken, got.AccessToken())
			assert.Equalf(tt.wantRefreshToken, got.RefreshToken(), "t.RefreshToken() = %v, want %v", tt.wantRefreshToken, got.RefreshToken())
			assert.Equalf(tt.wantExpiry, got.Expiry(), "t.Expiry() = %v, want %v", tt.wantExpiry, got.Expiry())
			assert.Equalf(tt.wantTokenSource, got.StaticTokenSource(), "t.StaticTokenSource() = %v, want %v", tt.wantTokenSource, got.StaticTokenSource())
			assert.Equalf(tt.wantExpired, got.IsExpired(), "t.Expired() = %v, want %v", tt.wantExpired, got.IsExpired())
			assert.Equalf(tt.wantValid, got.Valid(), "t.Valid() = %v, want %v", tt.wantValid, got.Valid())
			testAssertEqualFunc(t, tt.want.nowFunc, got.nowFunc, "now = %p,want %p", tt.want.nowFunc, got.nowFunc)
		})
	}
}

func TestUnmarshalClaims(t *testing.T) {
	// UnmarshalClaims testing is covered by other tests but we do have just a
	// few more test to add here.
	t.Parallel()
	t.Run("jwt-without-3-parts", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var claims map[string]interface{}
		jwt := "one.two"
		err := UnmarshalClaims(jwt, &claims)
		require.Error(err)
		assert.Truef(errors.Is(err, ErrInvalidParameter), "wanted \"%s\" but got \"%s\"", ErrInvalidParameter, err)
	})
}

func TestEffectiveClaims(t *testing.T) {
	t.Parallel()

	_, priv := TestGenerateKeys(t)
	testIat := float64(time.Now().Unix())
	testExp := float64(time.Now().Add(10 * time.Minute).Unix())
	testJWT := TestSignJWT(t, priv, string(ES256), map[string]any{
		"iss": "https://example.com/",
		"iat": testIat,
		"exp": testExp,
		"aud": []string{"www.example.com"},
		"sub": "alice@example.com",
	}, nil)

	t.Run("nil-claims", func(t *testing.T) {
		t.Parallel()
		tk := &Tk{idToken: IDToken(testJWT), additionalClaims: map[string]any{}}
		err := tk.EffectiveClaims(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilParameter)
		assert.ErrorContains(t, err, "v is nil")
	})
	t.Run("empty-id-token", func(t *testing.T) {
		t.Parallel()
		tk := &Tk{idToken: IDToken(""), additionalClaims: map[string]any{}}
		var claims map[string]any
		err := tk.EffectiveClaims(&claims)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParameter)
		assert.ErrorContains(t, err, "id_token is empty")
	})
	t.Run("no-additional-claims", func(t *testing.T) {
		t.Parallel()
		tk := &Tk{idToken: IDToken(testJWT), additionalClaims: map[string]any{}}
		var claims map[string]any
		err := tk.EffectiveClaims(&claims)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{
			"iss": "https://example.com/",
			"iat": testIat,
			"exp": testExp,
			"aud": []any{"www.example.com"},
			"sub": "alice@example.com",
		}, claims)
	})
	t.Run("azure-groups-overage", func(t *testing.T) {
		t.Parallel()
		tk := &Tk{
			idToken: IDToken(testJWT),
			additionalClaims: map[string]any{
				"groups": []any{"group-a", "group-b"},
			},
		}
		var claims map[string]any
		err := tk.EffectiveClaims(&claims)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{
			"iss":    "https://example.com/",
			"iat":    testIat,
			"exp":    testExp,
			"aud":    []any{"www.example.com"},
			"sub":    "alice@example.com",
			"groups": []any{"group-a", "group-b"},
		}, claims)
	})
	t.Run("id-token-wins-conflict", func(t *testing.T) {
		t.Parallel()
		tk := &Tk{
			idToken:          IDToken(testJWT),
			additionalClaims: map[string]any{"sub": "alice2@example.com"},
		}
		var claims map[string]any
		err := tk.EffectiveClaims(&claims)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{
			"iss": "https://example.com/",
			"iat": testIat,
			"exp": testExp,
			"aud": []any{"www.example.com"},
			"sub": "alice@example.com",
		}, claims)
	})
}
