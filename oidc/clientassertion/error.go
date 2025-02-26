// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import "errors"

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

	// algorithm errors

	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidSecretLength  = errors.New("invalid secret length for algorithm")
	ErrNilPrivateKey        = errors.New("nil private key")
)
