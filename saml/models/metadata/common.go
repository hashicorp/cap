// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package metadata

import "github.com/hashicorp/cap/saml/models/core"

/*
  This file defines common types used in defining SAML v2.0 Metadata elements and
  Attributes.
  See 2.2 Common Types - http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
*/

// EndpointType describes a SAML protocol binding endpoint at which a SAML entity can
// be sent protocol messages.
// See 2.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type Endpoint struct {
	Binding          core.ServiceBinding `xml:",attr"`
	Location         string              `xml:",attr"`
	ResponseLocation string              `xml:",attr,omitempty"`
}

// IndexedEndpointType extends EndpointType with a pair of attributes to permit the
// indexing of otherwise identical endpoints so that they can be referenced by protocol messages.
// See 2.2.3 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type IndexedEndpoint struct {
	Endpoint
	Index     int  `xml:"index,attr"`
	IsDefault bool `xml:"isDefault,attr,omitempty"`
}

// Localized is used to represent the SAML types:
// - localizedName
// - localizedURI
// See 2.2.4 & 2.2.5 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type Localized struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}
