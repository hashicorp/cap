package metadata

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var durationMarshalTests = []struct {
	in       time.Duration
	expected []byte
}{
	{0, nil},
	{time.Hour, []byte("PT1H")},
	{-time.Hour, []byte("-PT1H")},
}

func TestDuration(t *testing.T) {
	for i, testCase := range durationMarshalTests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual, err := Duration(testCase.in).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.expected, actual)
		})
	}
}

var durationUnmarshalTests = []struct {
	in       []byte
	expected time.Duration
	err      error
}{
	{nil, 0, nil},
	{[]byte("-PT1H"), -time.Hour, nil},
	{[]byte("P1D"), 24 * time.Hour, nil},
	{[]byte("P1M"), 720 * time.Hour, nil},
	{[]byte("PT1.S"), 0, errors.New("invalid duration (PT1.S)")},
}

func TestDurationUnmarshal(t *testing.T) {
	for i, testCase := range durationUnmarshalTests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var actual Duration
			err := actual.UnmarshalText(testCase.in)
			if testCase.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, testCase.err.Error())
			}
			require.Equal(t, Duration(testCase.expected), actual)
		})
	}
}
