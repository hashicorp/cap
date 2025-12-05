// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"

	"github.com/hashicorp/cap/oidc"
)

// RequestReader defines an interface for finding and reading an oidc.Request
//
// Implementations must be concurrently safe, since the reader will likely be
// used within a concurrent http.Handler
type RequestReader interface {
	// Read an existing Request entry.  The returned request's State()
	// must match the state used to look it up. Implementations must be
	// concurrently safe, which likely means returning a deep copy.
	Read(ctx context.Context, state string) (oidc.Request, error)
}

// SingleRequestReader implements the RequestReader interface for a single request.
// It is concurrently safe.
type SingleRequestReader struct {
	Request oidc.Request
}

// Read() will return it's single-request if the state matches it's Request.State(),
// otherwise it returns an error of oidc.ErrNotFound. It satisfies the
// RequestReader interface.  Read() is concurrently safe.
func (sr *SingleRequestReader) Read(ctx context.Context, state string) (oidc.Request, error) {
	if sr.Request.State() != state {
		return nil, oidc.ErrNotFound
	}
	return sr.Request, nil
}
