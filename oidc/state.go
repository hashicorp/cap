package oidc

import (
	"context"
	"time"

	"github.com/hashicorp/probo/sdk/id"
)

// StateReadWriter defines a common interface for reading/writing oidc state
type StateReadWriter interface {

	// Create a new oidc entry.  If optionalKey is provided it will be used as
	// the entry's unique key, otherwise a new unique key is created.  The
	// entry's unique key is returned on success.
	Create(ctx context.Context, value interface{}, optionalKey string) (key string, e error)

	// Update an existing state entry
	Update(ctx context.Context, key string, value interface{}) (e error)

	// Read an existing state entry
	Read(ctx context.Context, key string) (v interface{}, e error)

	// Delete an existing state entry
	Delete(ctx context.Context, key string) error
}

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for an OIDC state ID or nonce
func NewId(optionalPrefix string) (string, error) {
	id, err := id.New(optionalPrefix)
	if err != nil {
		return "", NewError(ErrIdGeneratorFailed, WithOp("oidc.NewId"), WithKind(ErrInternal), WithMsg("unable to generate id"), WithWrap(err))
	}
	return id, nil
}

// State represents the oidc state used for oidc flows.  The State.Id is passed
// throughout the flows to uniquely identify a specific flows state.
type State struct {
	Id          string
	Nonce       string
	RedirectURL string
	Expiration  time.Time
	Payload     interface{}
}

// NewState creates a new state in memory
func NewState(expireIn time.Duration, redirectURL string, payload interface{}) (*State, error) {
	const op = "oidc.NewState"
	if redirectURL == "" {
		return nil, NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("redirectURL is empty"))
	}
	nonce, err := NewId("n")
	if err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable to generate a state's nonce"))
	}

	id, err := NewId("st")
	if err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable to generate a state's id"))
	}

	return &State{
		Id:          id,
		Nonce:       nonce,
		RedirectURL: redirectURL,
		Expiration:  time.Now().Add(expireIn),
		Payload:     payload,
	}, nil
}

// IsExpired returns true if the state has expired
func (s *State) IsExpired() bool {
	return s.Expiration.Before(time.Now())
}
