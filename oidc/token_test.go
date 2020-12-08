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

	tests := []struct {
		name             string
		idToken          IDToken
		oauthToken       *oauth2.Token
		want             *Tk
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
			want: &Tk{
				idToken:    IDToken(testJWT),
				underlying: testUnderlying,
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
				idToken: IDToken(testJWT),
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
				idToken:    IDToken(testJWT),
				underlying: testUnderlyingZeroExpiry,
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
			got, err := NewToken(tt.idToken, tt.oauthToken)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.Equalf(tt.want, got, "NewToken() = %v, want %v", got, tt.want)

			assert.Equalf(tt.wantIDToken, got.IDToken(), "t.IDToken() = %v, want %v", tt.wantIDToken, got.IDToken())
			assert.Equalf(tt.wantAccessToken, got.AccessToken(), "t.AccessToken() = %v, want %v", tt.wantAccessToken, got.AccessToken())
			assert.Equalf(tt.wantRefreshToken, got.RefreshToken(), "t.RefreshToken() = %v, want %v", tt.wantRefreshToken, got.RefreshToken())
			assert.Equalf(tt.wantExpiry, got.Expiry(), "t.Expiry() = %v, want %v", tt.wantExpiry, got.Expiry())
			assert.Equalf(tt.wantTokenSource, got.StaticTokenSource(), "t.StaticTokenSource() = %v, want %v", tt.wantTokenSource, got.StaticTokenSource())
			assert.Equalf(tt.wantExpired, got.IsExpired(), "t.Expired() = %v, want %v", tt.wantExpired, got.IsExpired())
			assert.Equalf(tt.wantValid, got.Valid(), "t.Valid() = %v, want %v", tt.wantValid, got.Valid())
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
