package clientassertion

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/go-uuid"
)

const (
	// ClientAssertionJWTType is the proper value for client_assertion_type.
	// https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2
	ClientAssertionJWTType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

var (
	// these may happen due to user error
	ErrMissingClientID    = errors.New("missing client ID")
	ErrMissingAudience    = errors.New("missing audience")
	ErrMissingAlgorithm   = errors.New("missing signing algorithm")
	ErrMissingKeyOrSecret = errors.New("missing private key or client secret")
	ErrBothKeyAndSecret   = errors.New("both private key and client secret provided")
	// if these happen, either the user directly instantiated &ClientAssertion{}
	// or there's a bug somewhere.
	ErrMissingFuncIDGenerator = errors.New("missing IDgen func; please use New()")
	ErrMissingFuncNow         = errors.New("missing now func; please use New()")
)

// New sets up a new ClientAssertion to sign private key JWTs
func New(clientID string, audience []string, opts ...Option) (*ClientAssertion, error) {
	a := &ClientAssertion{
		clientID: clientID,
		audience: audience,
		headers:  make(map[string]string),
		genID:    uuid.GenerateUUID,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("new client assertion validation error: %w", err)
	}
	return a, nil
}

// ClientAssertion signs a JWT with either a private key or a secret
type ClientAssertion struct {
	// for JWT claims
	clientID string
	audience []string
	headers  map[string]string

	// for signer
	alg jose.SignatureAlgorithm
	// key may be any key type that jose.SigningKey accepts for its Key
	key any
	// secret may be used instead of key
	secret string

	// these are overwritten for testing
	genID func() (string, error)
	now   func() time.Time
}

// Validate validates the expected fields
func (c *ClientAssertion) Validate() error {
	var errs []error
	if c.genID == nil {
		errs = append(errs, ErrMissingFuncIDGenerator)
	}
	if c.now == nil {
		errs = append(errs, ErrMissingFuncNow)
	}
	// bail early if any internal func errors
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if c.clientID == "" {
		errs = append(errs, ErrMissingClientID)
	}
	if len(c.audience) == 0 {
		errs = append(errs, ErrMissingAudience)
	}
	if c.alg == "" {
		errs = append(errs, ErrMissingAlgorithm)
	}
	if c.key == nil && c.secret == "" {
		errs = append(errs, ErrMissingKeyOrSecret)
	}
	if c.key != nil && c.secret != "" {
		errs = append(errs, ErrBothKeyAndSecret)
	}
	return errors.Join(errs...)
}

// SignedToken returns a signed JWT in the compact serialization format
func (c *ClientAssertion) SignedToken() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	builder, err := c.builder()
	if err != nil {
		return "", err
	}
	token, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return token, nil
}

func (c *ClientAssertion) builder() (jwt.Builder, error) {
	signer, err := c.signer()
	if err != nil {
		return nil, err
	}
	id, err := c.genID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}
	claims := c.claims(id)
	return jwt.Signed(signer).Claims(claims), nil
}

func (c *ClientAssertion) signer() (jose.Signer, error) {
	sKey := jose.SigningKey{
		Algorithm: c.alg,
	}

	// Validate() ensures these are mutually exclusive
	if c.secret != "" {
		sKey.Key = []byte(c.secret)
	}
	if c.key != nil {
		sKey.Key = c.key
	}

	sOpts := &jose.SignerOptions{
		ExtraHeaders: make(map[jose.HeaderKey]interface{}, len(c.headers)),
	}
	// note: extra headers can override "kid"
	for k, v := range c.headers {
		sOpts.ExtraHeaders[jose.HeaderKey(k)] = v
	}

	signer, err := jose.NewSigner(sKey, sOpts.WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("failed to create jwt signer: %w", err)
	}
	return signer, nil
}

func (c *ClientAssertion) claims(id string) *jwt.Claims {
	now := c.now().UTC()
	return &jwt.Claims{
		Issuer:    c.clientID,
		Subject:   c.clientID,
		Audience:  c.audience,
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}
}

// Options configure the ClientAssertion
type Option func(*ClientAssertion)

// WithClientSecret sets a secret and algorithm to sign the JWT with
func WithClientSecret(secret string, alg string) Option {
	return func(c *ClientAssertion) {
		c.secret = secret
		c.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithRSAKey sets a private key to sign the JWT with
func WithRSAKey(key *rsa.PrivateKey, alg string) Option {
	return func(c *ClientAssertion) {
		c.key = key
		c.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithKeyID sets the "kid" header that OIDC providers use to look up the
// public key to check the signed JWT
func WithKeyID(keyID string) Option {
	return func(c *ClientAssertion) {
		c.headers["kid"] = keyID
	}
}

// WithHeaders sets extra JWT headers
func WithHeaders(h map[string]string) Option {
	return func(c *ClientAssertion) {
		for k, v := range h {
			c.headers[k] = v
		}
	}
}
