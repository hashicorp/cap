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
	// if these happen, either the user directly instantiated &JWT{}
	// or there's a bug somewhere.
	ErrMissingFuncIDGenerator = errors.New("missing IDgen func; please use NewJWT()")
	ErrMissingFuncNow         = errors.New("missing now func; please use NewJWT()")
)

// NewJWT sets up a new JWT to sign with a private key or client secret
func NewJWT(clientID string, audience []string, opts ...Option) (*JWT, error) {
	j := &JWT{
		clientID: clientID,
		audience: audience,
		headers:  make(map[string]string),
		genID:    uuid.GenerateUUID,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(j)
	}
	if err := j.Validate(); err != nil {
		return nil, fmt.Errorf("new client assertion validation error: %w", err)
	}
	return j, nil
}

// JWT signs a JWT with either a private key or a secret
type JWT struct {
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
func (j *JWT) Validate() error {
	var errs []error
	if j.genID == nil {
		errs = append(errs, ErrMissingFuncIDGenerator)
	}
	if j.now == nil {
		errs = append(errs, ErrMissingFuncNow)
	}
	// bail early if any internal func errors
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if j.clientID == "" {
		errs = append(errs, ErrMissingClientID)
	}
	if len(j.audience) == 0 {
		errs = append(errs, ErrMissingAudience)
	}
	if j.alg == "" {
		errs = append(errs, ErrMissingAlgorithm)
	}
	if j.key == nil && j.secret == "" {
		errs = append(errs, ErrMissingKeyOrSecret)
	}
	if j.key != nil && j.secret != "" {
		errs = append(errs, ErrBothKeyAndSecret)
	}
	return errors.Join(errs...)
}

// SignedToken returns a signed JWT in the compact serialization format
func (j *JWT) SignedToken() (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	builder, err := j.builder()
	if err != nil {
		return "", err
	}
	token, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return token, nil
}

func (j *JWT) builder() (jwt.Builder, error) {
	signer, err := j.signer()
	if err != nil {
		return nil, err
	}
	id, err := j.genID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}
	claims := j.claims(id)
	return jwt.Signed(signer).Claims(claims), nil
}

func (j *JWT) signer() (jose.Signer, error) {
	sKey := jose.SigningKey{
		Algorithm: j.alg,
	}

	// Validate() ensures these are mutually exclusive
	if j.secret != "" {
		sKey.Key = []byte(j.secret)
	}
	if j.key != nil {
		sKey.Key = j.key
	}

	sOpts := &jose.SignerOptions{
		ExtraHeaders: make(map[jose.HeaderKey]interface{}, len(j.headers)),
	}
	// note: extra headers can override "kid"
	for k, v := range j.headers {
		sOpts.ExtraHeaders[jose.HeaderKey(k)] = v
	}

	signer, err := jose.NewSigner(sKey, sOpts.WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("failed to create jwt signer: %w", err)
	}
	return signer, nil
}

func (j *JWT) claims(id string) *jwt.Claims {
	now := j.now().UTC()
	return &jwt.Claims{
		Issuer:    j.clientID,
		Subject:   j.clientID,
		Audience:  j.audience,
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}
}

// Options configure the JWT
type Option func(*JWT)

// WithClientSecret sets a secret and algorithm to sign the JWT with
func WithClientSecret(secret string, alg string) Option {
	return func(j *JWT) {
		j.secret = secret
		j.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithRSAKey sets a private key to sign the JWT with
func WithRSAKey(key *rsa.PrivateKey, alg string) Option {
	return func(j *JWT) {
		j.key = key
		j.alg = jose.SignatureAlgorithm(alg)
	}
}

// WithKeyID sets the "kid" header that OIDC providers use to look up the
// public key to check the signed JWT
func WithKeyID(keyID string) Option {
	return func(j *JWT) {
		j.headers["kid"] = keyID
	}
}

// WithHeaders sets extra JWT headers
func WithHeaders(h map[string]string) Option {
	return func(j *JWT) {
		for k, v := range h {
			j.headers[k] = v
		}
	}
}
