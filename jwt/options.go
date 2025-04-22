// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwt

// Option defines a common functional options type which can be used in a
// variadic parameter pattern.
type Option func(interface{})

type configOptions struct {
	withNormalizedAudiences bool
}

func configDefaults() configOptions {
	return configOptions{}
}

// getConfigOpts gets the defaults and applies the opt overrides passed
// in.
func getConfigOpts(opt ...Option) configOptions {
	opts := configDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

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

// WithNormalizedAudiences enables removing the trailing slash (if it exists) from all bound audiences
// before comparing against the aud claims.
func WithNormalizedAudiences() Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withNormalizedAudiences = true
		}
	}
}
