package saml

import "errors"

var (
	ErrInvalidParameter   = errors.New("invalid parameter")
	ErrBindingUnsupported = errors.New("configured binding unsupported by the IDP")
	ErrInvalidTLSCert     = errors.New("invalid tls certificate")
)
