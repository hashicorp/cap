// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

func TestApplyOpts(t *testing.T) {
	// ApplyOpts testing is covered by other tests but we do have just more
	// more test to add here.
	// Let's make sure we don't panic on nil options
	anonymousOpts := struct {
		Names []string
	}{
		nil,
	}
	ApplyOpts(anonymousOpts, nil)
}

func Test_WithNow(t *testing.T) {
	t.Parallel()
	testNow := func() time.Time {
		return time.Now().Add(-1 * time.Minute)
	}
	t.Run("tokenOptions", func(t *testing.T) {
		opts := getTokenOpts(WithNow(testNow))
		testOpts := tokenDefaults()
		testOpts.withNowFunc = testNow
		testAssertEqualFunc(t, opts.withNowFunc, testNow, "now = %p,want %p", opts.withNowFunc, testNow)
	})
	t.Run("reqOptions", func(t *testing.T) {
		opts := getReqOpts(WithNow(testNow))
		testOpts := reqDefaults()
		testOpts.withNowFunc = testNow
		testAssertEqualFunc(t, opts.withNowFunc, testNow, "now = %p,want %p", opts.withNowFunc, testNow)
	})
}

func Test_WithAudiences(t *testing.T) {
	t.Parallel()
	t.Run("configOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getConfigOpts(WithAudiences("alice", "bob"))
		testOpts := configDefaults()
		testOpts.withAudiences = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getConfigOpts(WithAudiences())
		testOpts = configDefaults()
		testOpts.withAudiences = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("reqOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getReqOpts(WithAudiences("alice", "bob"))
		testOpts := reqDefaults()
		testOpts.withAudiences = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithAudiences())
		testOpts = reqDefaults()
		testOpts.withAudiences = nil
		assert.Equal(opts, testOpts)
	})
}

func Test_WithScopes(t *testing.T) {
	t.Parallel()
	t.Run("configOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getConfigOpts(WithScopes("alice", "bob"))
		testOpts := configDefaults()
		testOpts.withScopes = []string{oidc.ScopeOpenID, "alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getConfigOpts(WithScopes())
		testOpts = configDefaults()
		testOpts.withScopes = []string{oidc.ScopeOpenID}
		assert.Equal(opts, testOpts)
	})
	t.Run("reqOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getReqOpts(WithScopes("alice", "bob"))
		testOpts := reqDefaults()
		testOpts.withScopes = []string{oidc.ScopeOpenID, "alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getReqOpts(WithScopes())
		testOpts = reqDefaults()
		testOpts.withScopes = nil
		assert.Equal(opts, testOpts)
	})
}
