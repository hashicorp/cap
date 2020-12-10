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

// WithNow provides an optional func for determining what the current time it is
// for: Config, Tk and St
func WithNow(now func() time.Time) Option {
	return func(o interface{}) {
		if now == nil {
			return
		}
		switch v := o.(type) {
		case *configOptions:
			v.withNowFunc = now
		case *tokenOptions:
			v.withNowFunc = now
		case *stOptions:
			v.withNowFunc = now
		}
	}
}
