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

// NewJWT creates a new JWT which will be signed with either a private key or
// client secret.
//
// Supported Options:
// * WithClientSecret
// * WithRSAKey
// * WithKeyID
// * WithHeaders
//
// Either WithRSAKey or WithClientSecret must be used, but not both.
func NewJWT(clientID string, audience []string, opts ...Option) (*JWT, error) {
	const op = "NewJWT"
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

	if err := j.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// finally, make sure Serialize() works; we can't pre-validate everything,
	// and this whole thing is useless if it can't Serialize()
	if _, err := j.Serialize(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return j, nil
}

// JWT is used to create a client assertion JWT, a special JWT used by an OAuth
// 2.0 or OIDC client to authenticate themselves to an authorization server
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

// Serialize returns client assertion JWT which can be used by an OAuth 2.0 or
// OIDC client to authenticate themselves to an authorization server
func (j *JWT) Serialize() (string, error) {
	const op = "JWT.Serialize"
	builder, err := j.builder()
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("%s: failed to serialize token: %w", op, err)
	}
	return token, nil
}

func (j *JWT) validate() error {
	const op = "JWT.validate"
	var errs []error
	if j.genID == nil {
		errs = append(errs, ErrMissingFuncIDGenerator)
	}
	if j.now == nil {
		errs = append(errs, ErrMissingFuncNow)
	}
	// bail early if any internal func errors
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", op, errors.Join(errs...))
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
		return fmt.Errorf("%s: %w", op, errors.Join(errs...))
	}

	return nil
}

func (j *JWT) builder() (jwt.Builder, error) {
	const op = "builder"
	signer, err := j.signer()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	id, err := j.genID()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to generate token id: %w", op, err)
	}
	claims := j.claims(id)
	return jwt.Signed(signer).Claims(claims), nil
}

func (j *JWT) signer() (jose.Signer, error) {
	const op = "signer"
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
	for k, v := range j.headers {
		sOpts.ExtraHeaders[jose.HeaderKey(k)] = v
	}

	signer, err := jose.NewSigner(sKey, sOpts.WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, ErrCreatingSigner, err)
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

// serializer is the primary interface impelmented by JWT.
type serializer interface {
	Serialize() (string, error)
}

// ensure JWT implements Serializer, which is accepted by the oidc option
// oidc.WithClientAssertionJWT.
var _ serializer = &JWT{}
