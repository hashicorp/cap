package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_WithExpirySkew(t *testing.T) {
	t.Parallel()
	exp := 10 * time.Millisecond
	t.Run("tokenOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getTokenOpts(WithExpirySkew(exp))
		testOpts := tokenDefaults()
		testOpts.withExpirySkew = exp
		assert.Equal(opts, testOpts)
	})
	t.Run("stOptions", func(t *testing.T) {
		assert := assert.New(t)
		opts := getStOpts(WithExpirySkew(exp))
		testOpts := stDefaults()
		testOpts.withExpirySkew = exp
		assert.Equal(opts, testOpts)
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
