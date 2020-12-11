package strutils

import (
	"reflect"
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

func TestStrUtil_RemoveDuplicatesStable(t *testing.T) {
	type tCase struct {
		input           []string
		expect          []string
		caseInsensitive bool
	}

	tCases := []tCase{
		{[]string{}, []string{}, false},
		{[]string{}, []string{}, true},
		{[]string{"a", "b", "a"}, []string{"a", "b"}, false},
		{[]string{"A", "b", "a"}, []string{"A", "b", "a"}, false},
		{[]string{"A", "b", "a"}, []string{"A", "b"}, true},
		{[]string{" ", "d", "c", "d"}, []string{"d", "c"}, false},
		{[]string{"Z ", " z", " z ", "y"}, []string{"Z ", "y"}, true},
		{[]string{"Z ", " z", " z ", "y"}, []string{"Z ", " z", "y"}, false},
	}

	for _, tc := range tCases {
		actual := RemoveDuplicatesStable(tc.input, tc.caseInsensitive)

		if !reflect.DeepEqual(actual, tc.expect) {
			t.Fatalf("Bad testcase %#v, expected %v, got %v", tc, tc.expect, actual)
		}
	}
}
