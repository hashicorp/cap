package oidc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewError(t *testing.T) {
	t.Parallel()

	isNilParameter := NewError(ErrNilParameter, WithMsg("missing config"), WithOp("alice.bob"), WithKind(ErrParameterViolation))
	tests := []struct {
		name string
		code Code
		opt  []Option
		want error
	}{
		{
			name: "all-options",
			code: ErrNilParameter,
			opt: []Option{
				WithOp("alice.Bob"),
				WithWrap(isNilParameter),
				WithMsg("test msg"),
			},
			want: &Err{
				Op:      "alice.Bob",
				Wrapped: isNilParameter,
				Msg:     "test msg",
				Code:    ErrNilParameter,
			},
		},
		{
			name: "no-options",
			opt:  nil,
			want: &Err{
				Code: ErrCodeUnknown,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := NewError(tt.code, tt.opt...)
			require.Error(err)
			assert.Equal(tt.want, err)
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	t.Parallel()
	testErr := NewError(ErrCodeUnknown, WithMsg("test error"))

	tests := []struct {
		name      string
		err       error
		want      error
		wantIsErr error
	}{
		{
			name:      "ErrInvalidParameter",
			err:       NewError(ErrInvalidParameter, WithWrap(testErr)),
			want:      testErr,
			wantIsErr: testErr,
		},
		{
			name:      "testErr",
			err:       testErr,
			want:      nil,
			wantIsErr: testErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			err := tt.err.(interface {
				Unwrap() error
			}).Unwrap()
			assert.Equal(tt.want, err)
			assert.True(errors.Is(tt.err, tt.wantIsErr))
		})
	}
	t.Run("nil *Err", func(t *testing.T) {
		assert := assert.New(t)
		var err *Err
		got := err.Unwrap()
		assert.Equal(nil, got)
	})
}

func TestConvertError(t *testing.T) {
	t.Parallel()

	testCode := Code(8675309)

	tests := []struct {
		name  string
		e     error
		match *ErrTemplate
	}{
		{
			name:  "nil",
			e:     nil,
			match: nil,
		},
		{
			name:  "not-convertible",
			e:     errors.New("test error"),
			match: nil,
		},
		{
			name:  "Jenny",
			e:     NewError(testCode),
			match: ErrT(testCode),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := ConvertError(tt.e)
			if tt.match == nil {
				assert.Nil(err)
				return
			}
			require.NotNil(err)
			assert.Truef(MatchError(tt.match, err), "errors did not match: %v != %v", tt.match, err)
		})
	}
}

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithMsg", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := getErrOpts()
		testOpts := errDefaults()
		testOpts.withErrMsg = ""
		assert.Equal(opts, testOpts)

		// try setting it
		opts = getErrOpts(WithMsg("test msg"))
		testOpts.withErrMsg = "test msg"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWrap", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := getErrOpts()
		testOpts := errDefaults()
		testOpts.withErrWrapped = nil
		assert.Equal(opts, testOpts)

		e := NewError(ErrInvalidParameter, WithOp("t.Run(WithWrap"))
		// try setting it
		opts = getErrOpts(WithWrap(e))
		testOpts.withErrWrapped = e
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOp", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := getErrOpts()
		testOpts := errDefaults()
		testOpts.withOp = ""
		assert.Equal(opts, testOpts)

		// try setting it
		opts = getErrOpts(WithOp("alice.bob"))
		testOpts.withOp = "alice.bob"
		assert.Equal(opts, testOpts)
	})
}
