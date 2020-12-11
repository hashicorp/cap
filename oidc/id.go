package oidc

import (
	"fmt"

	"github.com/hashicorp/cap/oidc/internal/base62"
)

// defaultIDLength is the default length for generated IDs
const defaultIDLength = 10

// NewID generates a ID with an optional prefix.   The ID generated is suitable
// for a State's ID or Nonce
func NewID(opt ...Option) (string, error) {
	const op = "NewID"
	opts := getIDOpts(opt...)
	id, err := base62.Random(opts.withLen)
	if err != nil {
		return "", fmt.Errorf("%s: unable to generate id: %w", op, err)
	}
	switch {
	case opts.withPrefix != "":
		return fmt.Sprintf("%s_%s", opts.withPrefix, id), nil
	default:
		return id, nil
	}
}

// idOptions is the set of available options.
type idOptions struct {
	withPrefix string
	withLen    int
}

// idDefaults is a handy way to get the defaults at runtime and
// during unit tests.
func idDefaults() idOptions {
	return idOptions{
		withLen: defaultIDLength,
	}
}

// getConfigOpts gets the defaults and applies the opt overrides passed
// in.
func getIDOpts(opt ...Option) idOptions {
	opts := idDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithPrefix provides an optional prefix for an new ID.  When this options is
// provided, NewID will prepend the prefix and an underscore to the new
// identifier. Valid for: ID
func WithPrefix(prefix string) Option {
	return func(o interface{}) {
		if o, ok := o.(*idOptions); ok {
			o.withPrefix = prefix
		}
	}
}
