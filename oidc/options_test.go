package oidc

import (
	"testing"
	"time"
)

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
