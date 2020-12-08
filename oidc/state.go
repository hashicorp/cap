package oidc

import (
	"fmt"
	"time"
)

// State basically represents one OIDC authentication flow for a user. It
// contains the data needed to uniquely represent that one-time flow across the
// multiple interactions needed to complete the OIDC flow the user is
// attempting.  ID() is passed throughout the OIDC interactions to uniquely
// identify the flow's state. The ID() and Nonce() cannot cannot be equal, and
// will be used during the OIDC flow to prevent CSRF and replay attacks (see the
// oidc spec for specifics).
type State interface {
	//	ID is a unique identifier and an opaque value used to maintain state
	//	between the oidc request and the callback. ID cannot equal the Nonce.
	ID() string

	//	Nonce is a unique nonce and a string value used to associate a Client
	//	session with an ID Token, and to mitigate replay attacks. Nonce cannot
	//	equal the ID
	Nonce() string

	// IsExpired returns true if the state has expired. Implementations should
	// supports a WithExpirySkew option and if none is provided it will use
	// a default skew (perhaps DefaultStateExpirySkew)
	IsExpired(opt ...Option) bool
}

// St represents the oidc state used for oidc flows.  The St.ID() is passed
// throughout the flows to uniquely identify a specific flow's state.
type St struct {
	//	id is a unique identifier and an opaque value used to maintain state
	//	between the oidc request and the callback
	id string

	// nonce is a unique nonce and suitable for use as an oidc nonce
	nonce string

	// Expiration is the expiration time for the State
	expiration time.Time
}

// ensure that St implements the State interface
var _ State = (*St)(nil)

// NewState creates a new State (*St)
func NewState(expireIn time.Duration) (*St, error) {
	const op = "oidc.NewState"
	nonce, err := NewID(WithPrefix("n"))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to generate a state's nonce: %w", op, err)
	}

	id, err := NewID(WithPrefix("st"))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to generate a state's id: %w", op, err)
	}
	if expireIn == 0 || expireIn < 0 {
		return nil, fmt.Errorf("%s: expireIn not greater than zero: %w", op, ErrInvalidParameter)
	}
	return &St{
		id:         id,
		nonce:      nonce,
		expiration: time.Now().Add(expireIn),
	}, nil
}

func (s *St) ID() string    { return s.id }    // ID implements the State.ID() interface function
func (s *St) Nonce() string { return s.nonce } // Nonce implements the State.Nonce() interface function

// DefaultStateExpirySkew defines a default time skew when checking a State's
// expiration.
const DefaultStateExpirySkew = 1 * time.Second

// IsExpired returns true if the state has expired. Supports the
// WithExpirySkew option and if none is provided it will use the
// DefaultStateExpirySkew.
func (s *St) IsExpired(opt ...Option) bool {
	opts := getStOpts(opt...)
	return s.expiration.Before(time.Now().Add(opts.withExpirySkew))
}

// stOptions is the set of available options for St functions
type stOptions struct {
	withExpirySkew time.Duration
}

// stDefaults is a handy way to get the defaults at runtime and during unit
// tests.
func stDefaults() stOptions {
	return stOptions{
		withExpirySkew: DefaultStateExpirySkew,
	}
}

// getStateOpts gets the state defaults and applies the opt overrides passed in
func getStOpts(opt ...Option) stOptions {
	opts := stDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}
