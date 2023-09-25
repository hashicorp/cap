// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metadata

import (
	"time"

	crewjamSaml "github.com/crewjam/saml"
)

// Duration is a time.Duration that uses the xsd:duration format for text
// marshalling and unmarshalling.
type Duration time.Duration

// MarshalText implements the encoding.TextMarshaler interface.
func (d Duration) MarshalText() ([]byte, error) {
	return crewjamSaml.Duration(d).MarshalText()
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (d *Duration) UnmarshalText(text []byte) error {
	cp := (*crewjamSaml.Duration)(d)
	return cp.UnmarshalText(text)
}
