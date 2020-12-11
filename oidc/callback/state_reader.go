package callback

import (
	"context"

	"github.com/hashicorp/cap/oidc"
)

// StateReader defines an interface for finding and reading an oidc.State
// Implementations must be concurrently safe, since the reader will likely be
// used within a concurrent http.Handler
type StateReader interface {
	// Read an existing AuthCodeState entry.  The returned state's ID()
	// must match the stateID used to look it up. Implementations must be
	// concurrently safe, which likely means returning a deep copy
	Read(ctx context.Context, stateID string) (oidc.State, error)
}

// SingleStateReader implements the StateReader interface for a single state.
// When it's Read() receiver function is called it will always return the same
// state.  It is concurrently safe.
type SingleStateReader struct {
	State oidc.State
}

// Read() will always return the same state and satisfies the StateReader
// interface.  Read() is concurrently safe.
func (s *SingleStateReader) Read(ctx context.Context, stateID string) (oidc.State, error) {
	return s.State, nil
}
