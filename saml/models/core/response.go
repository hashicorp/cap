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

func (r *Response) GetAssertion() *Assertion {
	if len(r.Assertion) == 0 {
		return nil
	}

	return r.Assertion[0]
}

func (r *Response) GetAssertionForIndex(index int) *Assertion {
	if (len(r.Assertion) - 1) < index {
		return nil
	}

	return r.Assertion[index]
}

// Issuer will return the issuer value from the Assertion.Issuer complext type.
func (a *Assertion) GetIssuer() string {
	return a.Issuer.Value
}

func (a *Assertion) GetIssuerFormat() string {
	return string(a.Issuer.Format)
}

// Subject will return the subject value from the Assertion.Subject complex type.
func (a *Assertion) GetSubject() string {
	return a.Subject.NameID.Value
}

// Subject will return the subject format value.
func (a *Assertion) GetSubjectFormat() string {
	return string(a.Subject.NameID.Format)
}
