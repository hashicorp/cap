// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// any non-nil error from NewJWT*() will be errors.Join()ed.
// this is so we can assert each error within.
type joinedErrs interface {
	Unwrap() []error
}

func assertJoinedErrs(t *testing.T, actual error, expect []error) {
	t.Helper()
	// New* error is wrapped, joined, wrapped errors
	err := errors.Unwrap(actual)
	joined, ok := err.(joinedErrs)
	require.True(t, ok, "expected Join()ed errors; got: %v", actual)
	unwrapped := joined.Unwrap()
	require.ElementsMatch(t, expect, unwrapped)
}

// TestJWTBare tests what errors we expect if &JWT{}
// is instantiated directly, rather than using a constructor.
func TestJWTBare(t *testing.T) {
	t.Parallel()

	j := &JWT{}

	tokenStr, err := j.Serialize()
	require.ErrorIs(t, err, ErrCreatingSigner)

	assert.Equal(t, "", tokenStr)
}

func TestNewJWTWithRSAKey(t *testing.T) {
	t.Parallel()

	cid := "test-client-id"
	aud := []string{"test-audience"}
	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		j, err := NewJWTWithRSAKey(cid, aud, RS256, validKey,
			WithKeyID("key-id"), WithHeaders(map[string]string{"foo": "bar"}))
		assert.NoError(t, err)
		assert.NotNil(t, j)
	})

	t.Run("multiple errors", func(t *testing.T) {
		j, err := NewJWTWithRSAKey("", []string{}, "", nil)
		assertJoinedErrs(t, err, []error{
			ErrMissingClientID, ErrMissingAudience, ErrMissingAlgorithm, ErrMissingKey,
		})
		assert.Nil(t, j)
	})
	t.Run("bad algorithm", func(t *testing.T) {
		_, err := NewJWTWithRSAKey(cid, aud, "bad-alg", &rsa.PrivateKey{})
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})
	t.Run("bad key", func(t *testing.T) {
		_, err = NewJWTWithRSAKey(cid, aud, RS256, &rsa.PrivateKey{})
		assert.ErrorContains(t, err, "RSAlgorithm.Validate: crypto/rsa")
	})
	t.Run("bad Options", func(t *testing.T) {
		_, err = NewJWTWithRSAKey(cid, aud, RS256, validKey,
			WithKeyID(""), WithHeaders(map[string]string{"kid": "baz"}))
		assert.ErrorIs(t, err, ErrMissingKeyID)
		assert.ErrorIs(t, err, ErrKidHeader)
	})
}

func TestNewJWTWithHMAC(t *testing.T) {
	t.Parallel()

	cid := "test-client-id"
	aud := []string{"test-audience"}
	validSecret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 bytes for HS256

	t.Run("happy path", func(t *testing.T) {
		j, err := NewJWTWithHMAC(cid, aud, HS256, validSecret,
			WithKeyID("key-id"), WithHeaders(map[string]string{"foo": "bar"}))
		assert.NoError(t, err)
		assert.NotNil(t, j)
	})

	t.Run("errors", func(t *testing.T) {
		j, err := NewJWTWithHMAC("", []string{}, "", "")
		assertJoinedErrs(t, err, []error{
			ErrMissingClientID, ErrMissingAudience, ErrMissingAlgorithm, ErrMissingSecret,
		})
		assert.Nil(t, j)
	})
	t.Run("bad algorithm", func(t *testing.T) {
		_, err := NewJWTWithHMAC(cid, aud, "bad-alg", validSecret)
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})
	t.Run("bad secret", func(t *testing.T) {
		_, err := NewJWTWithHMAC(cid, aud, HS256, "not-very-good")
		assert.ErrorIs(t, err, ErrInvalidSecretLength)
	})
	t.Run("bad Options", func(t *testing.T) {
		_, err := NewJWTWithHMAC(cid, aud, HS256, validSecret,
			WithKeyID(""), WithHeaders(map[string]string{"kid": "baz"}))
		assert.ErrorIs(t, err, ErrMissingKeyID)
		assert.ErrorIs(t, err, ErrKidHeader)
	})
}

func TestJWT_Serialize(t *testing.T) {
	t.Parallel()

	cid := "test-client-id"
	aud := []string{"test-audience"}

	// make the world more predictable
	now := time.Now()
	nowF := func() time.Time { return now }
	genIDF := func() (string, error) { return "test-claim-id", nil }

	// for rsa
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "couldn't get rsa.PublicKey from PrivateKey")
	// for hmac
	secret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 bytes for HS256

	// this specific shape is what this whole library is oriented around
	assertClaims := func(t *testing.T, token *jwt.JSONWebToken, key any) {
		t.Helper()
		expectClaims := jwt.Expected{
			Issuer:      "test-client-id",          // = cid
			Subject:     "test-client-id",          // = cid
			AnyAudience: []string{"test-audience"}, // = aud
			ID:          "test-claim-id",           // = genIDf()
			Time:        now,                       // = nowF()
		}
		var actualClaims jwt.Claims
		err := token.Claims(key, &actualClaims)
		require.NoError(t, err)
		err = actualClaims.Validate(expectClaims)
		require.NoError(t, err)
	}

	t.Run("rsa", func(t *testing.T) {
		j, err := NewJWTWithRSAKey(cid, aud, RS256, key,
			WithKeyID("key-id"), WithHeaders(map[string]string{"foo": "bar"}))
		require.NoError(t, err)
		require.NotNil(t, j)
		j.now = nowF
		j.genID = genIDF
		token, err := j.Serialize() // method under test
		require.NoError(t, err)
		require.NotEmpty(t, token)
		// make sure we made what we intended to
		parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		require.NotNil(t, parsed)
		expectHeaders := jose.Header{
			Algorithm: string(RS256),
			KeyID:     "key-id",
			ExtraHeaders: map[jose.HeaderKey]any{
				"typ": "JWT",
				"foo": "bar",
			},
		}
		require.Len(t, parsed.Headers, 1)
		actualHeaders := parsed.Headers[0]
		require.Equal(t, expectHeaders, actualHeaders)
		assertClaims(t, parsed, pub)
	})

	t.Run("hmac", func(t *testing.T) {
		j, err := NewJWTWithHMAC(cid, aud, HS256, secret,
			WithKeyID("key-id"), WithHeaders(map[string]string{"foo": "bar"}))
		require.NoError(t, err)
		require.NotNil(t, j)
		j.now = nowF
		j.genID = genIDF
		token, err := j.Serialize() // method under test
		require.NoError(t, err)
		require.NotEmpty(t, token)
		// make sure we made what we intended to
		parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
		require.NoError(t, err)
		require.NotNil(t, parsed)
		expectHeaders := jose.Header{
			Algorithm: string(HS256),
			KeyID:     "key-id",
			ExtraHeaders: map[jose.HeaderKey]any{
				"typ": "JWT",
				"foo": "bar",
			},
		}
		require.Len(t, parsed.Headers, 1)
		actualHeaders := parsed.Headers[0]
		require.Equal(t, expectHeaders, actualHeaders)
		assertClaims(t, parsed, []byte(secret))
	})

	t.Run("error generating token id", func(t *testing.T) {
		genIDErr := errors.New("failed to generate test id")
		j, err := NewJWTWithHMAC("a", []string{"a"}, HS256, secret)
		require.NoError(t, err)
		j.genID = func() (string, error) { return "", genIDErr }
		tokenString, err := j.Serialize()
		require.ErrorIs(t, err, genIDErr)
		require.Equal(t, "", tokenString)
	})
}
