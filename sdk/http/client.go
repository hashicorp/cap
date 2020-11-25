package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/go-cleanhttp"
)

var (
	ErrInvalidCertificatePem = errors.New("invalid certificate PEM")
)

// New creates a new http client which will use the optional CA certificate PEM
// if provided, otherwise it will use the installed system CA chain.
func NewClient(caPEM string) (*http.Client, error) {
	const op = "ProviderConfig.NewHTTPClient"
	tr := cleanhttp.DefaultPooledTransport()

	if caPEM != "" {
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(caPEM)); !ok {
			return nil, ErrInvalidCertificatePem
		}

		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	return &http.Client{
		Transport: tr,
	}, nil
}

// OidcClientContext is a helper function that returns a new Context that
// carries the provided HTTP client. This method sets the same context key used
// by the github.com/coreos/go-oidc and golang.org/x/oauth2 packages, so the
// returned context works for those packages as well.
func OidcClientContext(ctx context.Context, client *http.Client) context.Context {
	// simple to implement as a wrapper for the coreos package
	return oidc.ClientContext(ctx, client)
}
