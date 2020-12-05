package oidc

import (
	"fmt"

	"github.com/hashicorp/cap/oidc/internal/base62"
)

// DefaultIdLength is the default length for generated IDs
const DefaultIdLength = 10

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for a State's Id or Nonce
func NewId(opt ...Option) (string, error) {
	const op = "NewId"
	opts := getIdOpts(opt...)
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

// idOptions is the set of available options
type idOptions struct {
	withPrefix string
	withLen    int
}

// idDefaults is a handy way to get the defaults at runtime and
// during unit tests.
func idDefaults() idOptions {
	return idOptions{
		withLen: DefaultIdLength,
	}
}

// getConfigOpts gets the defaults and applies the opt overrides passed
// in.
func getIdOpts(opt ...Option) idOptions {
	opts := idDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithPrefix provides an optional prefix for an new ID
func WithPrefix(prefix string) Option {
	return func(o interface{}) {
		if o, ok := o.(*idOptions); ok {
			o.withPrefix = prefix
		}
	}
}
