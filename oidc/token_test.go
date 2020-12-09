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
	testJwt := testDefaultJwt(t, priv, 1*time.Minute, "123456789", nil)
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
		idToken          IdToken
		oauthToken       *oauth2.Token
		opts             []Option
		want             *Tk
		wantNowFunc      func() time.Time
		wantIdToken      IdToken
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
			idToken:    IdToken(testJwt),
			oauthToken: testUnderlying,
			opts:       []Option{WithNow(testNow)},
			want: &Tk{
				idToken:    IdToken(testJwt),
				underlying: testUnderlying,
				nowFunc:    testNow,
			},
			wantIdToken:      IdToken(testJwt),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlying),
			wantExpiry:       testExpiry,
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:       "valid-def-now-func",
			idToken:    IdToken(testJwt),
			oauthToken: testUnderlying,
			opts:       []Option{},
			want: &Tk{
				idToken:    IdToken(testJwt),
				underlying: testUnderlying,
			},
			wantIdToken:      IdToken(testJwt),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlying),
			wantExpiry:       testExpiry,
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:    "valid-without-accessToken",
			idToken: IdToken(testJwt),
			want: &Tk{
				idToken: IdToken(testJwt),
			},
			wantIdToken: IdToken(testJwt),
			wantExpired: true,
			wantValid:   false,
		},
		{
			name:       "valid-with-accessToken-and-zero-expiry",
			idToken:    IdToken(testJwt),
			oauthToken: testUnderlyingZeroExpiry,
			want: &Tk{
				idToken:    IdToken(testJwt),
				underlying: testUnderlyingZeroExpiry,
			},
			wantIdToken:      IdToken(testJwt),
			wantAccessToken:  AccessToken(testAccessToken),
			wantRefreshToken: RefreshToken(testRefreshToken),
			wantTokenSource:  oauth2.StaticTokenSource(testUnderlyingZeroExpiry),
			wantExpired:      false,
			wantValid:        true,
		},
		{
			name:    "empty-idToken",
			idToken: IdToken(""),
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
			assert.Equalf(tt.wantIdToken, got.IdToken(), "t.IdToken() = %v, want %v", tt.wantIdToken, got.IdToken())
			assert.Equalf(tt.wantAccessToken, got.AccessToken(), "t.AccessToken() = %v, want %v", tt.wantAccessToken, got.AccessToken())
			assert.Equalf(tt.wantRefreshToken, got.RefreshToken(), "t.RefreshToken() = %v, want %v", tt.wantRefreshToken, got.RefreshToken())
			assert.Equalf(tt.wantExpiry, got.Expiry(), "t.Expiry() = %v, want %v", tt.wantExpiry, got.Expiry())
			assert.Equalf(tt.wantTokenSource, got.StaticTokenSource(), "t.StaticTokenSource() = %v, want %v", tt.wantTokenSource, got.StaticTokenSource())
			assert.Equalf(tt.wantExpired, got.Expired(), "t.Expired() = %v, want %v", tt.wantExpired, got.Expired())
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
