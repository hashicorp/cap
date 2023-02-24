package core

import "encoding/xml"

type Response struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`

	StatusResponseType

	Status *Status
	Issuer *Issuer
}

// See 3.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusResponseType struct {
	RequestResponseCommon

	InResponseTo string  // optional
	Status       *Status // required
}

// See 3.2.2.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Status struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	StatusCode    StatusCode   // required
	StatusMessage string       // optional
	StatusDetail  StatusDetail // optional
}

// See 3.2.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`

	StatusCode StatusCodeType // optional
	Value      string         `xml:",attr"` // required
}

// See 3.2.2.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusMessage struct {
}

// See 3.2.2.4 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusDetail struct {
}
