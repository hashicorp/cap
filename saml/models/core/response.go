package core

import (
	"encoding/xml"
	"time"
)

type Response struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`

	StatusResponseType

	Assertion          []*Assertion
	EncryptedAssertion []*TBD
}

// See 3.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusResponseType struct {
	RequestResponseCommon

	InResponseTo string  `xml:",attr"` // optional
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

	// StatusCode StatusCodeType `xml:",attr,omitempty"` // optional TODO: Required?
	Value StatusCodeType `xml:",attr"` // required
}

// TODO
// See 3.2.2.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusMessage struct {
}

// TODO
// See 3.2.2.4 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusDetail struct {
}

// See 2.3.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Assertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	// attributes
	Version      string    `xml:",attr"` // required
	ID           string    `xml:",attr"` // required
	IssueInstant time.Time `xml:",attr"` // required

	Issuer *Issuer // required

	// Signature  *TBD     // optional
	Subject *Subject // optional
	// Conditions *TBD     // optional
	// Advice     *TBD     // optional

	// Statement          *TBD
	// AuthnStatement     *TBD
	// AuthzStatement     *TBD
	// AttributeStatement *TBD
}
