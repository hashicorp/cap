package oidc

import (
	"errors"
)

var (
	ErrInvalidParameter          = errors.New("Invalid parameter")
	ErrNilParameter              = errors.New("Nil parameter")
	ErrInvalidCACert             = errors.New("invalid CA certificate")
	ErrInvalidIssuer             = errors.New("invalid issuer")
	ErrIdGeneratorFailed         = errors.New("id generation failed")
	ErrExpiredState              = errors.New("state is expired")
	ErrResponseStateInvalid      = errors.New("todo")
	ErrMissingIdToken            = errors.New("id_token is missing")
	ErrIdTokenVerificationFailed = errors.New("todo")
	ErrInvalidSignature          = errors.New("invalid signature")
	ErrInvalidAudience           = errors.New("invalid audience")
	ErrInvalidNonce              = errors.New("invalid nonce")
	ErrNotFound                  = errors.New("not found")
	ErrLoginFailed               = errors.New("login failed")
	ErrUserInfoFailed            = errors.New("user info failed")
	ErrExchangeFailed            = errors.New("exchange failed")
)
