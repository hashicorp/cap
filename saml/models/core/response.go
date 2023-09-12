package core

import (
	"github.com/russellhaering/gosaml2/types"
)

// Response is a SAML Response element.
// See 3.3.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Response struct {
	types.Response
}

// Assertions returns the assertions in the Response.
func (r *Response) Assertions() []Assertion {
	assertions := make([]Assertion, 0, len(r.Response.Assertions))
	for _, assertion := range r.Response.Assertions {
		assertions = append(assertions, Assertion{Assertion: assertion})
	}

	return assertions
}

// Assertion is a SAML Assertion element.
// See 2.3.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Assertion struct {
	types.Assertion
}

// Attribute is a SAML Attribute element.
// See 2.7.3.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Attribute struct {
	types.Attribute
}

// SubjectNameID returns the value of the NameID element if it exists in
// the Assertion. Otherwise, it returns an empty string.
func (a *Assertion) SubjectNameID() string {
	if a.Subject == nil || a.Subject.NameID == nil {
		return ""
	}

	return a.Subject.NameID.Value
}

// Attributes returns the attributes of the Assertion. If there is no
// AttributeStatement or no contained Attributes, an empty list is returned.
func (a *Assertion) Attributes() []Attribute {
	if a.AttributeStatement == nil {
		return []Attribute{}
	}

	attributes := make([]Attribute, 0, len(a.AttributeStatement.Attributes))
	for _, attribute := range a.AttributeStatement.Attributes {
		attributes = append(attributes, Attribute{Attribute: attribute})
	}

	return attributes
}
