package oidc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
