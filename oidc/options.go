package oidc

import "time"

// Option defines a common functional options type which can be used in a
// variadic parameter pattern.
type Option func(interface{})

// ApplyOpts takes a pointer to the options struct as a set of default options
// and applies the slice of opts as overrides.
func ApplyOpts(opts interface{}, opt ...Option) {
	for _, o := range opt {
		if o == nil { // ignore any nil Options
			continue
		}
		o(opts)
	}
}

// WithExpirySkew provides an optional expiry skew duration for: Token, State
func WithExpirySkew(d time.Duration) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *tokenOptions:
			v.withExpirySkew = d
		case *stOptions:
			v.withExpirySkew = d
		}
	}
}
