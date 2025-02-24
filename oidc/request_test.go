// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc/internal/base62"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()
	skew := 250 * time.Millisecond
	defaultExpireIn := 1 * time.Second
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}

	testVerifier, err := NewCodeVerifier()
	require.NoError(t, err)

	tests := []struct {
		name                string
		expireIn            time.Duration
		redirectURL         string
		opts                []Option
		wantNowFunc         func() time.Time
		wantRedirectURL     string
		wantAudiences       []string
		wantScopes          []string
		wantVerifier        CodeVerifier
		wantClientAssertion string
		wantErr             bool
		wantIsErr           error
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
				WithClientAssertionJWT("test-client-assertion-jwt"),
			},
			wantNowFunc:         testNow,
			wantRedirectURL:     "https://bob.com",
			wantAudiences:       []string{"bob", "alice"},
			wantScopes:          []string{oidc.ScopeOpenID, "email", "profile"},
			wantVerifier:        testVerifier,
			wantClientAssertion: "test-client-assertion-jwt",
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
			got, err := NewRequest(tt.expireIn, tt.redirectURL, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			tExp := got.now().Add(tt.expireIn)
			assert.True(got.expiration.Before(tExp.Add(skew)))
			assert.True(got.expiration.After(tExp.Add(-skew)))
			assert.NotEqualf(got.State(), got.Nonce(), "%s id should not equal %s nonce", got.State(), got.Nonce())
			assert.NotEmpty(got.State())
			assert.NotEmpty(got.Nonce())
			testAssertEqualFunc(t, tt.wantNowFunc, got.nowFunc, "now = %p,want %p", tt.wantNowFunc, got.nowFunc)
			assert.Equalf(got.RedirectURL(), tt.wantRedirectURL, "wanted \"%s\" but got \"%s\"", tt.wantRedirectURL, got.RedirectURL())
			assert.Equalf(got.Audiences(), tt.wantAudiences, "wanted \"%s\" but got \"%s\"", tt.wantAudiences, got.Audiences())
			assert.Equalf(got.Scopes(), tt.wantScopes, "wanted \"%s\" but got \"%s\"", tt.wantScopes, got.Scopes())
			assert.Equalf(got.PKCEVerifier(), tt.wantVerifier, "wanted \"%s\" but got \"%s\"", tt.wantVerifier, got.PKCEVerifier())
			assert.Equal(got.ClientAssertionJWT(), tt.wantClientAssertion)
		})
	}
}

func TestRequest_IsExpired(t *testing.T) {
	t.Parallel()
	t.Run("not-expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r, err := NewRequest(2*time.Second, "https://redirect")
		require.NoError(err)
		assert.False(r.IsExpired())
	})
	t.Run("expired", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		oidcRequest, err := NewRequest(1*time.Nanosecond, "https://redirect")
		require.NoError(err)
		assert.True(oidcRequest.IsExpired())
	})
}

func Test_WithImplicit(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithImplicitFlow())
		testOpts = reqDefaults()
		testOpts.withImplicitFlow = &implicitFlow{}
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithImplicitFlow(true))
		testOpts = reqDefaults()
		testOpts.withImplicitFlow = &implicitFlow{true}
		assert.Equal(opts, testOpts)
	})
}

func Test_WithPKCE(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)
		assert.Nil(testOpts.withVerifier)

		v, err := NewCodeVerifier()
		require.NoError(err)
		opts = getReqOpts(WithPKCE(v))
		testOpts = reqDefaults()
		testOpts.withVerifier = v
		assert.Equal(opts, testOpts)
	})
}

func Test_WithClientAssertionJWT(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)
		assert.Empty(testOpts.withClientJWT)

		j := "test-jwt"
		opts = getReqOpts(WithClientAssertionJWT(j))
		testOpts = reqDefaults()
		testOpts.withClientJWT = j
		assert.Equal(opts, testOpts)
	})
}

func Test_WithMaxAge(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithMaxAge(1))
		testOpts = reqDefaults()
		// authAfter will be a zero value, since it's not set until the
		// NewRequest() factory, when it can determine it's nowFunc
		testOpts.withMaxAge = &maxAge{
			seconds: 1,
		}

		assert.Equal(opts, testOpts)
	})
}

func Test_WithPrompts(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithPrompts(Login, SelectAccount))
		testOpts = reqDefaults()

		testOpts.withPrompts = []Prompt{
			Login, SelectAccount,
		}

		assert.Equal(opts, testOpts)
	})
}

func Test_WithDisplay(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithDisplay(WAP))
		testOpts = reqDefaults()

		testOpts.withDisplay = WAP

		assert.Equal(opts, testOpts)
	})
}

func Test_WithUILocales(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithUILocales(language.AmericanEnglish, language.German))
		testOpts = reqDefaults()

		testOpts.withUILocales = []language.Tag{
			language.AmericanEnglish, language.German,
		}

		assert.Equal(opts, testOpts)
	})
}

func Test_WithClaims(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		const reqClaims = `
		{
			"userinfo":
			 {
			  "given_name": {"essential": true},
			  "nickname": null,
			  "email": {"essential": true},
			  "email_verified": {"essential": true},
			  "picture": null,
			  "http://example.info/claims/groups": null
			 },
			"id_token":
			 {
			  "auth_time": {"essential": true},
			  "acr": {"values": ["urn:mace:incommon:iap:silver"] }
			 }
		   }
		   `

		opts = getReqOpts(WithClaims([]byte(reqClaims)))
		testOpts = reqDefaults()

		testOpts.withClaims = []byte(reqClaims)
		assert.Equal(opts, testOpts)
	})
}

func Test_WithACRValues(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		// https://openid.net/specs/openid-connect-eap-acr-values-1_0.html#acrValues
		opts = getReqOpts(WithACRValues("phr", "phrh"))
		testOpts = reqDefaults()

		testOpts.withACRValues = []string{"phr", "phrh"}

		assert.Equal(opts, testOpts)
	})
}

func Test_WithState(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		s, err := base62.Random(128)
		require.NoError(t, err)

		opts = getReqOpts(WithState(s))
		testOpts = reqDefaults()

		testOpts.withState = s

		assert.Equal(opts, testOpts)
	})
}

func Test_WithNonce(t *testing.T) {
	t.Parallel()
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts()
		testOpts := reqDefaults()
		assert.Equal(opts, testOpts)

		n, err := base62.Random(128)
		require.NoError(t, err)

		opts = getReqOpts(WithNonce(n))
		testOpts = reqDefaults()

		testOpts.withNonce = n

		assert.Equal(opts, testOpts)
	})
}
