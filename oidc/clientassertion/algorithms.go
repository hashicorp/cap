package clientassertion

import (
	"crypto/rsa"
	"errors"
	"fmt"
)

type (
	SignatureAlgorithm string
	HSAlgorithm        SignatureAlgorithm
	RSAlgorithm        SignatureAlgorithm
)

const (
	HS256 HSAlgorithm = "HS256"
	HS384 HSAlgorithm = "HS384"
	HS512 HSAlgorithm = "HS512"
	RS256 RSAlgorithm = "RS256"
	RS384 RSAlgorithm = "RS384"
	RS512 RSAlgorithm = "RS512"
)

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidSecretLength  = errors.New("invalid secret length for algorithm")
)

func (a HSAlgorithm) Validate(secret string) error {
	// verify secret length based on alg
	var expectLen int
	switch a {
	case HS256:
		expectLen = 32
	case HS384:
		expectLen = 48
	case HS512:
		expectLen = 64
	default:
		return fmt.Errorf("%w %q for client secret", ErrUnsupportedAlgorithm, a)
	}
	if len(secret) < expectLen {
		return fmt.Errorf("%w: %q must be %d bytes long", ErrInvalidSecretLength, a, expectLen)
	}
	return nil
}

func (a RSAlgorithm) Validate(key *rsa.PrivateKey) error {
	switch a {
	case RS256, RS384, RS512:
		return key.Validate()
	default:
		return fmt.Errorf("%w %q for for RSA key", ErrUnsupportedAlgorithm, a)
	}
}
