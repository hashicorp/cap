// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/hashicorp/cap/oidc/internal/base62"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCodeVerifier(t *testing.T) {
	t.Run("basics", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got, err := NewCodeVerifier()
		require.NoError(err)
		assert.Equal(minVerifierLen, len(got.verifier))
		assert.Equal(S256, got.Method())

		challenge, err := CreateCodeChallenge(got)
		require.NoError(err)
		assert.Equal(challenge, got.Challenge())
	})
}

func TestCreateCodeChallenge(t *testing.T) {
	calcHash := func(data []byte) string {
		h := sha256.New()
		_, _ = h.Write(data)
		sum := h.Sum(nil)
		return base64.RawURLEncoding.EncodeToString(sum)
	}
	t.Run("basics", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v, err := NewCodeVerifier()
		require.NoError(err)
		challenge, err := CreateCodeChallenge(v)
		require.NoError(err)
		assert.Equal(calcHash([]byte(v.Verifier())), challenge)
	})
	t.Run("invalid-method", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v, err := NewCodeVerifier()
		require.NoError(err)
		v.method = ChallengeMethod("S512")
		challenge, err := CreateCodeChallenge(v)
		require.Error(err)
		assert.Empty(challenge)
		assert.True(errors.Is(err, ErrUnsupportedChallengeMethod))
	})
}

func Test_WithVerifier(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v, err := base62.Random(43)
	require.NoError(err)
	got, err := NewCodeVerifier(WithVerifier(v))
	require.NoError(err)
	assert.Equal(v, got.Verifier())

	// Test that the verifier is too short
	v, err = base62.Random(42)
	require.NoError(err)
	_, err = NewCodeVerifier(WithVerifier(v))
	require.Error(err)
	assert.Contains(err.Error(), "verifier length is less than 43")

	// Test that the verifier is too long
	v, err = base62.Random(129)
	require.NoError(err)
	_, err = NewCodeVerifier(WithVerifier(v))
	require.Error(err)
	assert.Contains(err.Error(), "verifier length is greater than 128")

	// Test that the verifier contains invalid characters
	v, err = base62.Random(43)
	require.NoError(err)
	v = v + "!"
	_, err = NewCodeVerifier(WithVerifier(v))
	require.Error(err)
	assert.Contains(err.Error(), "verifier contains invalid characters")
}
