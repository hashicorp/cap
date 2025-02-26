// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package clientassertion signs JWTs with a Private Key or Client Secret
// for use in OIDC client_assertion requests, A.K.A. private_key_jwt.
// reference: https://oauth.net/private-key-jwt/
package clientassertion

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-uuid"
)

const (
	// JWTTypeParam is the proper value for client_assertion_type.
	// https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2
	JWTTypeParam = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
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
	ErrCreatingSigner         = errors.New("error creating jwt signer")
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

	var errs []error
	for _, opt := range opts {
		if err := opt(j); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
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
	// if any of those fail, we have no hope.
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// finally, make sure Serialize() works; we can't pre-validate everything,
	// and this whole thing is useless if it can't Serialize()
	if _, err := j.Serialize(); err != nil {
		return fmt.Errorf("serialization error during validate: %w", err)
	}

	return nil
}

// Serialize returns a signed JWT string
func (j *JWT) Serialize() (string, error) {
	builder, err := j.builder()
	if err != nil {
		return "", err
	}
	token, err := builder.Serialize()
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
		return nil, fmt.Errorf("%w: %w", ErrCreatingSigner, err)
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

// Serializer is the primary interface impelmented by JWT.
type Serializer interface {
	Serialize() (string, error)
}

// ensure JWT implements Serializer, which is accepted by the oidc option
// oidc.WithClientAssertionJWT.
var _ Serializer = &JWT{}
