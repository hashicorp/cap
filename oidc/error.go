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
	ErrResponseStateInvalid      = errors.New("oidc response state")
	ErrMissingIdToken            = errors.New("id_token is missing")
	ErrIdTokenVerificationFailed = errors.New("id_token verification failed")
	ErrInvalidSignature          = errors.New("invalid signature")
	ErrInvalidAudience           = errors.New("invalid audience")
	ErrInvalidNonce              = errors.New("invalid nonce")
	ErrInvalidIssuedAt           = errors.New("invalid issued at (iat)")
	ErrInvalidAuthorizedParty    = errors.New("invalid authorized party (azp)")
	ErrInvalidAtHash             = errors.New("access_token hash does not match value in id_token")
	ErrTokenNotSigned            = errors.New("token is not signed")
	ErrMalformedToken            = errors.New("token malformed")
	ErrUnsupportedAlg            = errors.New("unsupported signing algorithm")
	ErrNotFound                  = errors.New("not found")
	ErrLoginFailed               = errors.New("login failed")
	ErrUserInfoFailed            = errors.New("user info failed")
)
