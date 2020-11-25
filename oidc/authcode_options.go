package oidc

import "golang.org/x/oauth2"

type authCodeProviderOptions struct {
	withNonce oauth2.AuthCodeOption
}

func providerDefaults() authCodeProviderOptions {
	return authCodeProviderOptions{}
}

func getAuthCodeProviderOpts(opt ...Option) authCodeProviderOptions {
	opts := providerDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithNonce provides a nonce to use as an OAuth2 nonce parameter
func WithNonce(nonce string) Option {
	return func(o interface{}) {
		if o, ok := o.(*authCodeProviderOptions); ok {
			o.withNonce = oauth2.SetAuthURLParam("nonce", nonce)
		}
	}
}
