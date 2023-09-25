// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metadata

import (
	"encoding/xml"

	"github.com/hashicorp/cap/saml/models/core"
)

// IDPSSODescriptor contains profiles specific to identity providers supporting SSO.
// It extends the SSODescriptor type.
// See 2.4.3 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type IDPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`

	SSODescriptor

	WantAuthnRequestsSigned   bool `xml:",attr"`
	SingleSignOnService       []Endpoint
	NameIDMappingService      []Endpoint // TODO test missing!
	AssertionIDRequestService []Endpoint // TODO test missing!
	AttributeProfile          []string   // TODO test missing!
	Attribute                 []Attribute
}

// EntityDescriptorIDPSSO is an EntityDescriptor that accommodates the IDPSSODescriptor
// as descriptor field only.
type EntityDescriptorIDPSSO struct {
	EntityDescriptor

	IDPSSODescriptor []*IDPSSODescriptor
}

func (e *EntityDescriptorIDPSSO) GetLocationForBinding(b core.ServiceBinding) (string, bool) {
	for _, isd := range e.IDPSSODescriptor {
		for _, ssos := range isd.SingleSignOnService {
			if ssos.Binding == b {
				return ssos.Location, true
			}
		}
	}

	return "", false
}
