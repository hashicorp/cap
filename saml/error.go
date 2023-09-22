package saml

import "errors"

var (
	ErrInternal             = errors.New("internal error")
	ErrBindingUnsupported   = errors.New("Configured binding unsupported by the IDP")
	ErrInvalidTLSCert       = errors.New("invalid tls certificate")
	ErrInvalidParameter     = errors.New("invalid parameter")
	ErrMissingAssertions    = errors.New("missing assertions")
	ErrInvalidTime          = errors.New("invalid time")
	ErrInvalidAudience      = errors.New("invalid audience")
	ErrMissingSubject       = errors.New("subject missing")
	ErrMissingAttributeStmt = errors.New("attribute statement missing")
)
