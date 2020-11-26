package oidc

import (
	"time"
)

// State defines an interface for the representation an oidc state used for
// oidc flows.  Id() is passed throughout the flows to uniquely identify a
// specific flow's state.
type State interface {
	//	Id is a unique identifier and an opaque value used to maintain state
	//	between the oidc request and the callback
	Id() string

	// RedirectURL is the redirection URL that the authentication response will
	// be sent. This URL must exactly match one of the redirection URL values
	// for the Client pre-registered at the OpenID Provider,
	RedirectURL() string

	//	Nonce is a unique nonce and a string value used to associate a Client
	//	session with an ID Token, and to mitigate replay attacks.
	Nonce() string

	// IsExpired returns true if the state has expired. Implementations should
	// supports a WithExpirySkew option and if none is provided it will use the
	// a default skew (perhaps DefaultStateExpirySkew)
	IsExpired(opt ...Option) bool
}

// St represents the oidc state used for oidc flows.  The St.Id()1 is passed
// throughout the flows to uniquely identify a specific flow's state.
type St struct {
	//	id is a unique identifier and an opaque value used to maintain state
	//	between the oidc request and the callback
	id string

	// nonce is a unique nonce and suitable for use as an oidc nonce
	nonce string

	// redirectURL is the authentication response URL
	redirectURL string

	// Expiration is the expiration time for the State
	expiration time.Time

	// Payload is any additional payload need by the process using the State
	Payload interface{}
}

// ensure that St implements the State interface
var _ State = (*St)(nil)

// NewState creates a new state in memory
func NewState(expireIn time.Duration, redirectURL string, payload interface{}) (State, error) {
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

	return &St{
		id:          id,
		nonce:       nonce,
		redirectURL: redirectURL,
		expiration:  time.Now().Add(expireIn),
		Payload:     payload,
	}, nil
}

func (s *St) Id() string          { return s.id }          // Id implements the State.Id() interface function
func (s *St) RedirectURL() string { return s.redirectURL } // RedirectURL implements the State.RedirectURL() interface function
func (s *St) Nonce() string       { return s.nonce }       // Nonce implements the Nonce.Id() interface function

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
