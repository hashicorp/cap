package clientassertion

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// any non-nil error from NewJWT()/Validate() will be errors.Join()ed.
// this is so we can assert each error within.
type joinedErrs interface {
	Unwrap() []error
}

func assertJoinedErrs(t *testing.T, expect []error, actual error) {
	t.Helper()
	joined, ok := actual.(joinedErrs) // Validate() error is errors.Join()ed
	require.True(t, ok, "expected Join()ed errors from Validate()")
	unwrapped := joined.Unwrap()
	require.ElementsMatch(t, expect, unwrapped)
}

// TestJWTBare tests what errors we expect if &JWT{}
// is instantiated directly, rather than using the constructor NewJWT().
func TestJWTBare(t *testing.T) {
	j := &JWT{}

	// all public methods should return the same error(s)
	expect := []error{ErrMissingFuncIDGenerator, ErrMissingFuncNow}

	actual := j.Validate()
	assertJoinedErrs(t, expect, actual)

	tokenStr, err := j.SignedToken()
	assertJoinedErrs(t, expect, err)

	assert.Equal(t, "", tokenStr)
}

func TestNewJWT(t *testing.T) {
	t.Run("should run validate", func(t *testing.T) {
		j, err := NewJWT("", nil)
		require.ErrorContains(t, err, "validation error:")
		assert.Nil(t, j)
	})

	tCid := "test-client-id"
	tAud := []string{"test-audience"}

	cases := []struct {
		name  string
		cid   string
		aud   []string
		opts  []Option
		check func(*testing.T, *JWT)
	}{
		{
			name: "with private key",
			cid:  tCid, aud: tAud,
			opts: []Option{WithRSAKey(&rsa.PrivateKey{}, "test-alg")},
			check: func(t *testing.T, ca *JWT) {
				require.NotNil(t, ca.key)
				require.Equal(t, jose.SignatureAlgorithm("test-alg"), ca.alg)
			},
		},
		{
			name: "with client secret",
			cid:  tCid, aud: tAud,
			opts: []Option{WithClientSecret("ssshhhh", "test-alg")},
			check: func(t *testing.T, ca *JWT) {
				require.Equal(t, "ssshhhh", ca.secret)
				require.Equal(t, jose.SignatureAlgorithm("test-alg"), ca.alg)
			},
		},
		{
			name: "with key id",
			cid:  tCid, aud: tAud,
			opts: []Option{
				WithKeyID("kid"),
				WithClientSecret("ssshhhh", "blah"),
			},
			check: func(t *testing.T, ca *JWT) {
				require.Equal(t, "kid", ca.headers["kid"])
			},
		},
		{
			name: "with headers",
			cid:  tCid, aud: tAud,
			opts: []Option{
				WithHeaders(map[string]string{"h1": "v1", "h2": "v2"}),
				WithClientSecret("ssshhhh", "test-alg"),
			},
			check: func(t *testing.T, ca *JWT) {
				require.Equal(t, map[string]string{"h1": "v1", "h2": "v2"}, ca.headers)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			j, err := NewJWT(tc.cid, tc.aud, tc.opts...)

			require.NoError(t, err)
			require.NotNil(t, j)
			require.Equal(t, tc.cid, j.clientID)
			require.Equal(t, tc.aud, j.audience)

			if tc.check != nil {
				tc.check(t, j)
			}

		})
	}
}

func TestValidate(t *testing.T) {
	tCid := "test-client-id"
	tAud := []string{"test-audience"}
	cases := []struct {
		name string
		cid  string
		aud  []string
		opts []Option
		errs []error
	}{
		{
			name: "missing everything",
			errs: []error{ErrMissingClientID, ErrMissingAudience, ErrMissingAlgorithm, ErrMissingKeyOrSecret},
		},
		{
			name: "missing client id",
			aud:  tAud,
			errs: []error{ErrMissingClientID},
			opts: []Option{
				WithRSAKey(&rsa.PrivateKey{}, "algo"),
			},
		},
		{
			name: "missing audience",
			cid:  tCid,
			errs: []error{ErrMissingAudience},
			opts: []Option{
				WithRSAKey(&rsa.PrivateKey{}, "algo"),
			},
		},
		{
			name: "missing client and secret",
			cid:  tCid, aud: tAud,
			errs: []error{ErrMissingAlgorithm, ErrMissingKeyOrSecret},
		},
		{
			name: "both client and secret",
			cid:  tCid, aud: tAud,
			opts: []Option{
				WithRSAKey(&rsa.PrivateKey{}, "algo"),
				WithClientSecret("ssshhhh", "algo"),
			},
			errs: []error{ErrBothKeyAndSecret},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			// NewJWT() runs Validate()
			j, err := NewJWT(tc.cid, tc.aud, tc.opts...)

			require.NotNil(t, err)
			require.ErrorContains(t, err, "validation error:")

			err = errors.Unwrap(err) // NewJWT wraps the error from Validate() with fmt.Errorf("%w")
			assertJoinedErrs(t, tc.errs, err)

			require.Nil(t, j)

		})
	}
}

func TestSignedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "couldn't get rsa.PublicKey from PrivateKey")

	cases := []struct {
		name     string
		claimKey any // []byte or pubkey; we'll use this to check the signature
		opts     []Option
		err      error
	}{
		{
			name:     "valid secret",
			claimKey: []byte("ssshhhh"),
			opts: []Option{
				WithClientSecret("ssshhhh", "HS256"),
				WithKeyID("test-key-id"),
				WithHeaders(map[string]string{"xtra": "headies"}),
			},
		},
		{
			name:     "valid key",
			claimKey: pub,
			opts: []Option{
				WithRSAKey(key, "RS256"),
				WithKeyID("test-key-id"),
				WithHeaders(map[string]string{"xtra": "headies"}),
			},
		},
		{
			name:     "invalid alg",
			claimKey: pub,
			opts: []Option{
				WithRSAKey(key, "ruh-roh"),
			},
			err: jose.ErrUnsupportedAlgorithm,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j, err := NewJWT("test-client-id", []string{"test-aud"}, tc.opts...)
			require.NoError(t, err)

			now := time.Now()
			j.now = func() time.Time { return now }
			j.genID = func() (string, error) { return "test-claim-id", nil }

			// method under test
			tokenString, err := j.SignedToken()

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Equal(t, "", tokenString)
				return
			}
			require.NoError(t, err)

			// extract the token from the signed string
			token, err := jwt.ParseSigned(tokenString)
			require.NoError(t, err)

			// check headers
			expectHeaders := jose.Header{
				Algorithm: string(j.alg),
				KeyID:     "test-key-id",
				ExtraHeaders: map[jose.HeaderKey]any{
					"typ":  "JWT",
					"xtra": "headies",
				},
			}
			require.Len(t, token.Headers, 1)
			actualHeaders := token.Headers[0]
			require.Equal(t, expectHeaders, actualHeaders)

			// check claims
			expectClaims := jwt.Expected{
				Issuer:   "test-client-id",
				Subject:  "test-client-id",
				Audience: []string{"test-aud"},
				ID:       "test-claim-id",
				Time:     now,
			}
			var actualClaims jwt.Claims
			err = token.Claims(tc.claimKey, &actualClaims)
			require.NoError(t, err)
			err = actualClaims.Validate(expectClaims)
			require.NoError(t, err)
		})
	}

	t.Run("error generating token id", func(t *testing.T) {
		genIDErr := errors.New("failed to generate test id")
		j, err := NewJWT("a", []string{"a"}, WithClientSecret("ssshhhh", "HS256"))
		require.NoError(t, err)
		j.genID = func() (string, error) { return "", genIDErr }
		tokenString, err := j.SignedToken()
		require.ErrorIs(t, err, genIDErr)
		require.Equal(t, "", tokenString)
	})
}
