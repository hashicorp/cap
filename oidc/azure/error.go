// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package azure

import "errors"

var (
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrNilParameter     = errors.New("nil parameter")
)
