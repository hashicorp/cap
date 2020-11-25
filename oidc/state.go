package oidc

import (
	"time"

	"github.com/hashicorp/probo/sdk/id"
)

// DefaultStateExpirySkew defines a default time skew when checking a State's
// expiration.
const DefaultStateExpirySkew = 1 * time.Second

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for an OIDC State's Id or Nonce
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
	Id          string      // Id is a unique identifier and suitable for use as an oidc state
	Nonce       string      // Nonce is a unique nonce and suitable for use as an oidc nonce
	RedirectURL string      // RedirectURL is the URL to redirect users going through the OAuth flow, after the resource owner's URLs.
	Expiration  time.Time   // Expiration is the expiration time for the State
	Payload     interface{} // Payload is any additional payload need by the process using the State
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

// IsExpired returns true if the state has expired. Supports the
// WithExpirySkew option and if none is provided it will use the
// DefaultStateExpirySkew.
func (s *State) IsExpired(opt ...Option) bool {
	opts := getStateOpts(opt...)
	return s.Expiration.Before(time.Now().Add(opts.withExpirySkew))
}

// stateOptions is the set of available options for State functions
type stateOptions struct {
	withExpirySkew time.Duration
}

// stateDefaults is a handy way to get the defaults at runtime and during unit
// tests.
func stateDefaults() stateOptions {
	return stateOptions{
		withExpirySkew: DefaultStateExpirySkew,
	}
}

// getStateOpts gets the state defaults and applies the opt overrides passed in
func getStateOpts(opt ...Option) stateOptions {
	opts := stateDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}
