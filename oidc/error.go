package oidc

import (
	"errors"
	"fmt"
	"strings"
)

type Code uint32
type Kind uint32
type Op string

const (
	ErrCodeUnknown Code = iota
	ErrInvalidParameter
	ErrNilParameter
	ErrInvalidCACert
	ErrInvalidIssuer
	ErrIdGeneratorFailed
	ErrExpiredState
	ErrResponseStateInvalid
	ErrCodeExchangeFailed
	ErrMissingIdToken
	ErrIdTokenVerificationFailed
	ErrInvalidSignature
	ErrInvalidAudience
	ErrInvalidNonce
	ErrNotFound
	ErrLoginFailed
	ErrUserInfoFailed
)

const (
	ErrKindUnknown Kind = iota
	ErrInternal
	ErrParameterViolation
	ErrIntegrityViolation
	ErrLoginViolation
)

func (k Kind) String() string {
	list := [...]string{
		"unknown violation",
		"parameter violation",
		"integrity violation",
	}
	if int(k) > len(list)-1 {
		return fmt.Sprintf("%d is an classified kind of error", k)
	}
	return list[k]
}

type Err struct {
	// Code is the error's code
	Code Code

	// Kind is the kind of error raised (classification)
	Kind Kind

	// Msg for the error
	Msg string

	// Op represents the operation raising/propagating an error and is optional
	Op Op

	// Wrapped is the error which this Err wraps and will be nil if there's no
	// error to wrap.
	Wrapped error
}

// NewError creates a new memory with the given Code and options.
func NewError(c Code, opt ...Option) error {
	opts := getErrOpts(opt...)
	if c == 0 {
		c = ErrCodeUnknown
	}
	return &Err{
		Code:    c,
		Kind:    opts.withKind,
		Op:      opts.withOp,
		Msg:     opts.withErrMsg,
		Wrapped: opts.withErrWrapped,
	}
}

// WrapError an error
func WrapError(e error, opt ...Option) error {
	err := ConvertError(e)
	if err != nil {
		opt = append(opt, WithWrap(err))
		return NewError(err.Code, opt...)
	}

	// e is not an oidc error or it could not be converted to one
	opt = append(opt, WithWrap(e))
	return NewError(ErrCodeUnknown, opt...)
}

// ConvertError will convert the error to a Boundary *Err (returning it as an error)
// and attempt to add a helpful error msg as well. If that's not possible, it
// will return nil
func ConvertError(e error) *Err {
	if e == nil {
		return nil
	}
	var oidcErr *Err
	if errors.As(e, &oidcErr) {
		return oidcErr
	}
	// unfortunately, we can't help
	return nil
}

// Error satisfies the error interface and returns a string representation of
// the Err
func (e *Err) Error() string {
	if e == nil {
		return ""
	}
	var s strings.Builder
	if e.Op != "" {
		join(&s, ": ", string(e.Op))
	}
	var skipInfo bool
	var wrapped *Err
	if errors.As(e.Wrapped, &wrapped) {
		// if wrapped error code is the same as this error, don't print redundant info
		skipInfo = wrapped.Code == e.Code
	}
	if !skipInfo {
		if e.Kind != 0 {
			join(&s, ": ", e.Kind.String())
		}
		if e.Msg != "" {
			join(&s, ": ", e.Msg)
		}
		join(&s, ": ", fmt.Sprintf("error #%d", e.Code))
	}

	if e.Wrapped != nil {
		join(&s, ": ", e.Wrapped.Error())
	}
	return s.String()
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Err) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Wrapped
}

func join(str *strings.Builder, delim string, s string) {
	if str.Len() == 0 {
		_, _ = str.WriteString(s)
		return
	}
	_, _ = str.WriteString(delim + s)
}

// ErrTemplate is useful constructing Match Err templates.  Templates allow you to
// match Errs without specifying a Code.  In other words, just Match using the
// Errs: Kind, Op, etc.
type ErrTemplate struct {
	Err       // Err embedded to support matching Errs
	Kind Kind // Kind allows explicit matching on a Template without a Code.
}

// T creates a new Template for matching Errs.  Invalid parameters are ignored.
// If more than is one parameter for a given type, only the last one is used.
func ErrT(args ...interface{}) *ErrTemplate {
	t := &ErrTemplate{}
	for _, a := range args {
		switch arg := a.(type) {
		case Code:
			t.Code = arg
		case string:
			t.Msg = arg
		case Op:
			t.Op = arg
		case *Err: // order is important, this match must before "case error:"
			c := *arg
			t.Wrapped = &c
		case error:
			t.Wrapped = arg
		case Kind:
			t.Kind = arg
		default:
			// ignore it
		}
	}
	return t
}

// Error satisfies the error interface but we intentionally don't return
// anything of value, in an effort to stop users from substituting Templates in
// place of Errs, when creating domain errors.
func (t *ErrTemplate) Error() string {
	return "Template error"
}

// MatchError the template against the error.  The error must be a *Err, or match
// will return false.  Matches all non-empty fields of the template against the
// error.
func MatchError(t *ErrTemplate, err error) bool {
	if t == nil || err == nil {
		return false
	}
	e, ok := err.(*Err)
	if !ok {
		return false
	}

	if t.Code != ErrCodeUnknown && t.Code != e.Code {
		return false
	}
	if t.Msg != "" && t.Msg != e.Msg {
		return false
	}
	if t.Op != "" && t.Op != e.Op {
		return false
	}
	if t.Kind != ErrKindUnknown && t.Kind != e.Kind {
		return false
	}
	if t.Wrapped != nil {
		if wrappedT, ok := t.Wrapped.(*ErrTemplate); ok {
			return MatchError(wrappedT, e.Wrapped)
		}
		if e.Wrapped != nil && t.Wrapped.Error() != e.Wrapped.Error() {
			return false
		}
	}

	return true
}

// errOptions is the set of available options
type errOptions struct {
	withErrWrapped error
	withErrMsg     string
	withOp         Op
	withKind       Kind
}

func errDefaults() errOptions {
	return errOptions{}
}

func getErrOpts(opt ...Option) errOptions {
	opts := errDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithWrap provides an optional error to wrap for a new error
func WithWrap(e error) Option {
	return func(o interface{}) {
		if o, ok := o.(*errOptions); ok {
			o.withErrWrapped = e
		}
	}
}

// WithMsg provides an optional message for an error
func WithMsg(msg string) Option {
	return func(o interface{}) {
		if o, ok := o.(*errOptions); ok {
			o.withErrMsg = msg
		}
	}
}

// WithOp provides an optional operation (name) that's raising/propagating
// the error.
func WithOp(op Op) Option {
	return func(o interface{}) {
		if o, ok := o.(*errOptions); ok {
			o.withOp = op
		}
	}
}

// WithKind provides an optional Kind (category) for an error.
func WithKind(k Kind) Option {
	return func(o interface{}) {
		if o, ok := o.(*errOptions); ok {
			o.withKind = k
		}
	}
}
