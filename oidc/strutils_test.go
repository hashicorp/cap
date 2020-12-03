package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStrutil_ListContains(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	haystack := []string{
		"dev",
		"ops",
		"prod",
		"root",
	}
	require.False(StrListContains(haystack, "tubez"))
	require.True(StrListContains(haystack, "root"))
}
