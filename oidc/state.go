package oidc

import (
	"fmt"
	"time"

	"golang.org/x/text/language"
)

// State basically represents one OIDC authentication flow for a user. It
// contains the data needed to uniquely represent that one-time flow across the
// multiple interactions needed to complete the OIDC flow the user is
// attempting.
//
// ID() is passed throughout the OIDC interactions to uniquely identify the
// flow's state. The ID() and Nonce() cannot be equal, and will be used during
// the OIDC flow to prevent CSRF and replay attacks (see the oidc spec for
// specifics).
//
// Audiences and Scopes are optional overrides of configured provider defaults
// for specific authentication attempts
type State interface {
	// ID is a unique identifier and an opaque value used to maintain state
	// between the oidc request and the callback. ID cannot equal the Nonce.
	// See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
	ID() string

	// Nonce is a unique nonce and a string value used to associate a Client
	// session with an ID Token, and to mitigate replay attacks. Nonce cannot
	// equal the ID.
	// See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// and https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes.
	Nonce() string

	// IsExpired returns true if the state has expired. Implementations should
	// support a time skew (perhaps StateExpirySkew) when checking expiration.
	IsExpired() bool

	// Audiences is an specific authentication attempt's list of optional
	// case-sensitive strings to use when verifying an id_token's "aud" claim
	// (which is also a list). If provided, the audiences of an id_token must
	// match one of the configured audiences.  If a State does not have
	// audiences, then the configured list of default audiences will be used.
	Audiences() []string

	// Scopes is a specific authentication attempt's list of optional
	// scopes to request of the provider. The required "oidc" scope is requested
	// by default, and does not need to be part of this optional list. If a
	// State does not have Scopes, then the configured list of default
	// requested scopes will be used.
	Scopes() []string

	// RedirectURL is a URL where providers will redirect responses to
	// authentication requests.
	RedirectURL() string

	// ImplicitFlow indicates whether or not to use the implicit flow with form
	// post. Getting only an id_token for an implicit flow should be the
	// default for implementations, but at times it's necessary to also request
	// an access_token, so this function and the WithImplicitFlow(...) option
	// allows for those scenarios. Overall, it is recommend to not request
	// access_tokens during the implicit flow.  If you need an access_token,
	// then use the authorization code flows and if you can't secure a client
	// secret then use the authorization code flow with PKCE.
	//
	// The first returned bool represents if the implicit flow has been requested.
	// The second returned bool represents if an access token has been requested
	// during the implicit flow.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
	// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
	ImplicitFlow() (useImplicitFlow bool, includeAccessToken bool)

	// PKCEVerifier indicates whether or not to use the authorization code flow
	// with PKCE.  PKCE should be used for any client which cannot secure a
	// client secret (SPA and native apps) or is susceptible to authorization
	// code intercept attacks. When supported by your OIDC provider, PKCE should
	// be used instead of the implicit flow.
	//
	// See: https://tools.ietf.org/html/rfc7636
	PKCEVerifier() CodeVerifier

	// MaxAge: when authAfter is not a zero value (authTime.IsZero()) then the
	// id_token's auth_time claim must be after the specified time.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	MaxAge() (seconds uint, authAfter time.Time)

	// Prompts optionally defines a list of values that specifies whether the
	// Authorization Server prompts the End-User for reauthentication and
	// consent.  See MaxAge() if wish to specify an allowable elapsed time in
	// seconds since the last time the End-User was actively authenticated by
	// the OP.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	Prompts() []Prompt

	// Display optionally specifies how the Authorization Server displays the
	// authentication and consent user interface pages to the End-User.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	Display() Display

	// UILocales optionally specifies End-User's preferred languages via
	// language Tags, ordered by preference.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	UILocales() []language.Tag

	// RequestClaims optionally requests that specific claims be returned using
	// the claims parameter.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
	RequestClaims() []byte

	// ACRValues() optionally specifies the acr values that the Authorization
	// Server is being requested to use for processing this Authentication
	// Request, with the values appearing in order of preference.
	//
	// NOTE: Requested acr_values are not verified by the Provider.Exchange(...)
	// or Provider.VerifyIDToken() functions, since the request/return values
	// are determined by the provider's implementation. You'll need to verify
	// the claims returned yourself based on values provided by you OIDC
	// Provider's documentation.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	ACRValues() []string
}

// St represents the oidc state used for oidc flows and implements the State interface.
type St struct {
	//	id is a unique identifier and an opaque value used to maintain state
	//	between the oidc request and the callback.
	id string

	// nonce is a unique nonce and suitable for use as an oidc nonce.
	nonce string

	// Expiration is the expiration time for the State.
	expiration time.Time

	// redirectURL is a URL where providers will redirect responses to
	// authentication requests.
	redirectURL string

	// scopes is a specific authentication attempt's list of optional
	// scopes to request of the provider. The required "oidc" scope is requested
	// by default, and does not need to be part of this optional list. If a
	// State does not have Scopes, then the configured list of default
	// requested scopes will be used.
	scopes []string

	// audiences is an specific authentication attempt's list of optional
	// case-sensitive strings to use when verifying an id_token's "aud" claim
	// (which is also a list). If provided, the audiences of an id_token must
	// match one of the configured audiences.  If a State does not have
	// audiences, then the configured list of default audiences will be used.
	audiences []string

	// nowFunc is an optional function that returns the current time
	nowFunc func() time.Time

	// withImplicit indicates whether or not to use the implicit flow.  Getting
	// only an id_token for an implicit flow is the default. If an access_token
	// is also required, then withImplicit.includeAccessToken will be true. It
	// is recommend to not request access_tokens during the implicit flow.  If
	// you need an access_token, then use the authorization code flows (with
	// optional PKCE).
	withImplicit *implicitFlow

	// withVerifier indicates whether or not to use the authorization code flow
	// with PKCE.  It suppies the required CodeVerifier for PKCE.
	withVerifier CodeVerifier

	// withMaxAge: when withMaxAge.authAfter is not a zero value
	// (authTime.IsZero()) then the id_token's auth_time claim must be after the
	// specified time.
	withMaxAge *maxAge

	// withPrompts optionally defines a list of values that specifies whether
	// the Authorization Server prompts the End-User for reauthentication and
	// consent.
	withPrompts []Prompt

	// withDisplay optionally specifies how the Authorization Server displays the
	// authentication and consent user interface pages to the End-User.
	withDisplay Display

	// withUILocales optionally specifies End-User's preferred languages via
	// language Tags, ordered by preference.
	withUILocales []language.Tag

	// withRequestClaims optionally requests that specific claims be returned
	// using the claims parameter.
	withRequestClaims []byte

	// withACRValues() optionally specifies the acr values that the Authorization
	// Server is being requested to use for processing this Authentication
	// Request, with the values appearing in order of preference.
	withACRValues []string
}

// ensure that St implements the State interface.
var _ State = (*St)(nil)

// NewState creates a new State (*St).
//  Supports the options:
//   * WithNow
//   * WithAudiences
//   * WithScopes
//   * WithImplicit
//   * WithPKCE
//   * WithMaxAge
//   * WithPrompts
//   * WithDisplay
//   * WithUILocales
//   * WithRequestClaims
func NewState(expireIn time.Duration, redirectURL string, opt ...Option) (*St, error) {
	const op = "oidc.NewState"
	opts := getStOpts(opt...)
	if redirectURL == "" {
		return nil, fmt.Errorf("%s: redirect URL is empty: %w", op, ErrInvalidParameter)
	}
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
	if opts.withVerifier != nil && opts.withImplicitFlow != nil {
		return nil, fmt.Errorf("%s: requested both implicit flow and authorization code with PKCE: %w", op, ErrInvalidParameter)

	}
	s := &St{
		id:                id,
		nonce:             nonce,
		redirectURL:       redirectURL,
		nowFunc:           opts.withNowFunc,
		audiences:         opts.withAudiences,
		scopes:            opts.withScopes,
		withImplicit:      opts.withImplicitFlow,
		withVerifier:      opts.withVerifier,
		withPrompts:       opts.withPrompts,
		withDisplay:       opts.withDisplay,
		withUILocales:     opts.withUILocales,
		withRequestClaims: opts.withRequestClaims,
		withACRValues:     opts.withACRValues,
	}
	s.expiration = s.now().Add(expireIn)
	if opts.withMaxAge != nil {
		opts.withMaxAge.authAfter = s.now().Add(time.Duration(-opts.withMaxAge.seconds) * time.Second)
		s.withMaxAge = opts.withMaxAge
	}
	return s, nil
}

// ID implements the State.ID() interface function.
func (s *St) ID() string { return s.id }

// Nonce implements the State.Nonce() interface function.
func (s *St) Nonce() string { return s.nonce }

// Audiences implements the State.Audiences() interface function and returns a
// copy of the audiences.
func (s *St) Audiences() []string {
	if s.audiences == nil {
		return nil
	}
	cp := make([]string, len(s.audiences))
	copy(cp, s.audiences)
	return cp
}

// Scopes implements the State.Scopes() interface function and returns a copy of
// the scopes.
func (s *St) Scopes() []string {
	if s.scopes == nil {
		return nil
	}
	cp := make([]string, len(s.scopes))
	copy(cp, s.scopes)
	return cp
}

// RedirectURL implements the State.RedirectURL() interface function.
func (s *St) RedirectURL() string { return s.redirectURL }

// PKCEVerifier implements the State.PKCEVerifier() interface function and
// returns a copy of the CodeVerifier
func (s *St) PKCEVerifier() CodeVerifier {
	if s.withVerifier == nil {
		return nil
	}
	return s.withVerifier.Copy()
}

// Prompts() implements the State.Prompts() interface function and returns a
// copy of the prompts.
func (s *St) Prompts() []Prompt {
	if s.withPrompts == nil {
		return nil
	}
	cp := make([]Prompt, len(s.withPrompts))
	copy(cp, s.withPrompts)
	return cp
}

// Display() implements the State.Display() interface function.
func (s *St) Display() Display { return s.withDisplay }

// UILocales() implements the State.UILocales() interface function and returns a
// copy of the UILocales
func (s *St) UILocales() []language.Tag {
	if s.withUILocales == nil {
		return nil
	}
	cp := make([]language.Tag, len(s.withUILocales))
	copy(cp, s.withUILocales)
	return cp
}

// RequestClaims() implements the State.RequestClaims() interface function
// and returns a copy of the claims request.
func (s *St) RequestClaims() []byte {
	if s.withRequestClaims == nil {
		return nil
	}
	cp := make([]byte, len(s.withRequestClaims))
	copy(cp, s.withRequestClaims)
	return cp
}

// ACRValues() implements the State.ARCValues() interface function and returns a
// copy of the acr values
func (s *St) ACRValues() []string {
	if len(s.withACRValues) == 0 {
		return nil
	}
	cp := make([]string, len(s.withACRValues))
	copy(cp, s.withACRValues)
	return cp
}

// MaxAge: when authAfter is not a zero value (authTime.IsZero()) then the
// id_token's auth_time claim must be after the specified time.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func (s *St) MaxAge() (uint, time.Time) {
	if s.withMaxAge == nil {
		return 0, time.Time{}
	}
	return s.withMaxAge.seconds, s.withMaxAge.authAfter.Truncate(time.Second)
}

// ImplicitFlow indicates whether or not to use the implicit flow.  Getting
// only an id_token for an implicit flow is the default, but at times
// it's necessary to also request an access_token, so this function and the
// WithImplicitFlow(...) option allows for those scenarios. Overall, it is
// recommend to not request access_tokens during the implicit flow.  If you need
// an access_token, then use the authorization code flows and if you can't
// secure a client secret then use the authorization code flow with PKCE.
//
// The first returned bool represents if the implicit flow has been requested.
// The second returned bool represents if an access token has been requested
// during the implicit flow.
func (s *St) ImplicitFlow() (bool, bool) {
	if s.withImplicit == nil {
		return false, false
	}
	switch {
	case s.withImplicit.withAccessToken:
		return true, true
	default:
		return true, false
	}
}

// StateExpirySkew defines a time skew when checking a State's expiration.
const StateExpirySkew = 1 * time.Second

// IsExpired returns true if the state has expired.
func (s *St) IsExpired() bool {
	return s.expiration.Before(time.Now().Add(StateExpirySkew))
}

// now returns the current time using the optional timeFn
func (s *St) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now() // fallback to this default
}

type implicitFlow struct {
	withAccessToken bool
}

type maxAge struct {
	seconds   uint
	authAfter time.Time
}

// stOptions is the set of available options for St functions
type stOptions struct {
	withNowFunc       func() time.Time
	withScopes        []string
	withAudiences     []string
	withImplicitFlow  *implicitFlow
	withVerifier      CodeVerifier
	withMaxAge        *maxAge
	withPrompts       []Prompt
	withDisplay       Display
	withUILocales     []language.Tag
	withRequestClaims []byte
	withACRValues     []string
}

// stDefaults is a handy way to get the defaults at runtime and during unit
// tests.
func stDefaults() stOptions {
	return stOptions{}
}

// getStateOpts gets the state defaults and applies the opt overrides passed in
func getStOpts(opt ...Option) stOptions {
	opts := stDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithImplicitFlow provides an option to use an OIDC implicit flow with form
// post. It should be noted that if your OIDC provider supports PKCE, then use
// it over the implicit flow.  Getting only an id_token is the default, and
// optionally passing a true bool will request an access_token as well during
// the flow.  You cannot use WithImplicit and WithPKCE together.  It is
// recommend to not request access_tokens during the implicit flow.  If you need
// an access_token, then use the authorization code flows.
//
// Option is valid for: St
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
func WithImplicitFlow(args ...interface{}) Option {
	withAccessToken := false
	for _, arg := range args {
		switch arg := arg.(type) {
		case bool:
			if arg {
				withAccessToken = true
			}
		}
	}
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withImplicitFlow = &implicitFlow{
				withAccessToken: withAccessToken,
			}
		}
	}
}

// WithPKCE provides an option to use a CodeVerifier with the authorization
// code flow with PKCE.  You cannot use WithImplicit and WithPKCE together.
//
// Option is valid for: St
//
// See: https://tools.ietf.org/html/rfc7636
func WithPKCE(v CodeVerifier) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withVerifier = v
		}
	}
}

// WithMaxAge provides an optional maximum authentication age, which is the
// allowable elapsed time in seconds since the last time the user was actively
// authenticated by the provider.  When a max age is specified, the provider
// must include a auth_time claim in the returned id_token.  This makes it
// preferable to prompt=login, where you have no way to verify when an
// authentication took place.
//
// Option is valid for: St
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithMaxAge(seconds uint) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			// authAfter will be a zero value, since it's not set until the
			// NewState() factory, when it can determine it's nowFunc
			o.withMaxAge = &maxAge{
				seconds: seconds,
			}
		}
	}
}

// WithPrompts provides an optional list of values that specifies whether the
// Authorization Server prompts the End-User for reauthentication and consent.
//
// See MaxAge() if wish to specify an allowable elapsed time in seconds since
// the last time the End-User was actively authenticated by the OP.
//
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithPrompts(prompts ...Prompt) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withPrompts = prompts
		}
	}
}

// WithDisplay optionally specifies how the Authorization Server displays the
// authentication and consent user interface pages to the End-User.
//
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithDisplay(d Display) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withDisplay = d
		}
	}
}

// WithUILocales optionally specifies End-User's preferred languages via
// language Tags, ordered by preference.
//
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithUILocales(locales ...language.Tag) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withUILocales = locales
		}
	}
}

// WithRequestClaims optionally requests that specific claims be returned using
// the claims parameter.
//
// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
func WithRequestClaims(json []byte) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withRequestClaims = json
		}
	}
}

// WithACRValues optionally specifies the acr values that the Authorization
// Server is being requested to use for processing this Authentication
// Request, with the values appearing in order of preference.
//
// NOTE: Requested acr_values are not verified by the Provider.Exchange(...)
// or Provider.VerifyIDToken() functions, since the request/return values
// are determined by the provider's implementation. You'll need to verify
// the claims returned yourself based on values provided by you OIDC
// Provider's documentation.
//
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithACRValues(values ...string) Option {
	return func(o interface{}) {
		if o, ok := o.(*stOptions); ok {
			o.withACRValues = values
		}
	}
}
