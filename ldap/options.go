package ldap

import (
	"crypto/tls"
)

// Option defines a common functional options type which can be used in a
// variadic parameter pattern.
type Option func(interface{})

type configOptions struct {
	withTLSConfig     *tls.Config
	withURLs          []string
	withInsecureTLS   bool
	withTLSMinVersion string
	withTLSMaxVersion string
	withCertificate   string
	withClientTLSCert string
	withClientTLSKey  string
	withGroups        bool
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

// WithURLs provides a set of optional ldap URLs for directory services
func WithURLs(urls ...string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withURLs = urls
		}
	}
}

// WithTLSConfig provides an optional tls.Config
func WithTLSConfig(tc *tls.Config) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withTLSConfig = tc
		}
	}
}

// WithGroups requests that the groups be included in the response.
func WithGroups() Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withGroups = true
		}
	}
}

func withTLSMinVersion(version string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withTLSMinVersion = version
		}
	}
}

func withTLSMaxVersion(version string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withTLSMaxVersion = version
		}
	}
}

func withInsecureTLS(withInsecure bool) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withInsecureTLS = withInsecure
		}
	}
}

func withCertificate(cert string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withCertificate = cert
		}
	}
}

func withClientTLSKey(key string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withClientTLSKey = key
		}
	}
}

func withClientTLSCert(cert string) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withClientTLSCert = cert
		}
	}
}
