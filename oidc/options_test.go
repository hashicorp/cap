package oidc

import (
	"testing"
	"time"

	"github.com/coreos/go-oidc"
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
	t.Run("stOptions", func(t *testing.T) {
		opts := getStOpts(WithNow(testNow))
		testOpts := stDefaults()
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
	t.Run("stOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getStOpts(WithAudiences("alice", "bob"))
		testOpts := stDefaults()
		testOpts.withAudiences = []string{"alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getStOpts(WithAudiences())
		testOpts = stDefaults()
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
	t.Run("stOptions", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		opts := getStOpts(WithScopes("alice", "bob"))
		testOpts := stDefaults()
		testOpts.withScopes = []string{oidc.ScopeOpenID, "alice", "bob"}
		assert.Equal(opts, testOpts)

		opts = getStOpts(WithScopes())
		testOpts = stDefaults()
		testOpts.withScopes = nil
		assert.Equal(opts, testOpts)
	})
}
