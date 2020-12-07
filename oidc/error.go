package oidc

import (
	"errors"
)

var (
	ErrInvalidParameter          = errors.New("invalid parameter")
	ErrNilParameter              = errors.New("nil parameter")
	ErrInvalidCACert             = errors.New("invalid CA certificate")
	ErrInvalidIssuer             = errors.New("invalid issuer")
	ErrIdGeneratorFailed         = errors.New("id generation failed")
	ErrExpiredState              = errors.New("state is expired")
	ErrResponseStateInvalid      = errors.New("oidc response state")
	ErrMissingIdToken            = errors.New("id_token is missing")
	ErrIdTokenVerificationFailed = errors.New("id_token verification failed")
	ErrInvalidSignature          = errors.New("invalid signature")
	ErrInvalidAudience           = errors.New("invalid audience")
	ErrInvalidNonce              = errors.New("invalid nonce")
	ErrNotFound                  = errors.New("not found")
	ErrLoginFailed               = errors.New("login failed")
	ErrUserInfoFailed            = errors.New("user info failed")
)
