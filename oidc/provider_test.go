package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithImplicitFlow(t *testing.T) {

	t.Parallel()
	assert := assert.New(t)
	opts := getProviderOpts(WithImplicitFlow())
	testOpts := providerDefaults()
	testOpts.withImplicitFlow = &implicitFlow{withoutAccessToken: false}
	assert.Equal(opts, testOpts)

	opts = getProviderOpts(WithImplicitFlow(true))
	testOpts = providerDefaults()
	testOpts.withImplicitFlow = &implicitFlow{withoutAccessToken: true}
	assert.Equal(opts, testOpts)
}
