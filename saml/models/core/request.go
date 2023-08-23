package core

import (
	"encoding/xml"
	"strings"
	"time"
)

// See 3.2.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusRequestType struct {
	RequestResponseCommon
}

// See 3.4.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
// TODO Finish this
type AuthnRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`

	StatusRequestType

	Subject              *Subject
	NameIDPolicy         *NameIDPolicy `xml:",omitempty"`
	Conditions           *Conditions
	RequestedAuthContext *RequestedAuthnContext
	Scoping              *Scoping

	ForceAuthn bool `xml:",attr,omitempty"`
	IsPassive  bool `xml:",attr,omitempty"`

	AssertionConsumerServiceIndex string `xml:",attr,omitempty"`
	AssertionConsumerServiceURL   string `xml:",attr"`

	// A URI reference that identifies a SAML protocol binding to be used when
	// returning the Response message.
	ProtocolBinding ServiceBinding `xml:",attr"`

	AttributeConsumingServiceIndex string `xml:",attr,omitempty"`
	ProviderName                   string `xml:",attr,omitempty"`
}

// Subject specifies the requested subject of the resulting assertion(s).
// If entirely omitted or if no identifier is included, the presenter of
// the message is presumed to be the requested subject.
//
// See 2.4 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Subject struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`

	BaseID              *BaseID
	NameID              *NameID
	EncryptionID        string
	SubjectConfirmation []*SubjectConfirmation
}

// See 2.4.1.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmation struct {
	Method ConfirmationMethod `xml:",attr"` // required

	SubjectConfirmationData *SubjectConfirmationData // optional

	BaseID      *BaseID      // optional
	NameID      *NameID      // optional
	EncryptedID *EncryptedID // optional
}

// See 2.4.1.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmationData struct {
	NotBefore    time.Time `xml:",attr"` // optional
	NotOnOrAfter time.Time `xml:",attr"` // optional
	Recipient    string    `xml:",attr"` // optional
	InResponseTo string    `xml:",attr"` // optional
	Address      string    `xml:",attr"` // optional
}

/* TODO: Create a function to validate this:
Note that the time period specified by the optional NotBefore and NotOnOrAfter attributes, if present,
SHOULD fall within the overall assertion validity period as specified by the <Conditions> element's
NotBefore and NotOnOrAfter attributes. If both attributes are present, the value for NotBefore
MUST be less than (earlier than) the value for NotOnOrAfter.
*/

// NameIDPolicy specifies constraints on the name identifier to be used to represent
// the requested subject.
// See 3.4.1.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	Format          NameIDFormat `xml:",omitempty"`
	SPNameQualifier string       `xml:",attr,omitempty"`
	AllowCreate     bool         `xml:",attr"`
}

// Scoping ... (TODO: not important for the first MVP)
// See 3.4.1.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Scoping struct {
	// ProxyCount specifies the number of proxying indirections permissible between the
	// identity provider that receives this AuthnRequest and the identity provider who
	// ultimately authenticates the principal.
	ProxyCount int `xml:",attr"`

	IDPList *IDPList

	RequesterID []string
}

// IDPList specifies the identity providers trusted by the requester to authenticate the
// presenter.
// See 3.4.1.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type IDPList struct {
	IDPEntry    []*IDPEntry
	GetComplete []string // TODO is this correct?
}

// IDPEntry specifies a single identity provider trusted by the requester to authenticate the
// presenter.
// See 3.4.1.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type IDPEntry struct {
	// ProividerID is the unique identifier of the identity provider.
	ProviderID string `xml:",attr"`

	// Name is a human-readable name for the identity provider.
	Name string

	// Loc is a URI reference representing the location of a profile-specific endpoint
	// supporting the authentication request protocol.
	Loc string
}

type Conditions struct{}

// Comparison specifies the comparison method used to evaluate the requested context classes or statements.
// Possible values: "exact", "minimum", "maximum", "better"
type Comparison string

const (
	// ComparisonExact requires that the resulting authentication context in the authentication
	// statement MUST be the exact match of at least one of the authentication contexts specified.
	ComparisonExact Comparison = "exact" // default

	// ComparisonMin requires that the resulting authentication context in the authentication
	// statement MUST be at least as strong (as deemed by the responder) as one of the authentication
	// contexts specified.
	ComparsionMin Comparison = "minimum"

	// ComparisonMax requires that the resulting authentication context in the authentication
	// statement MUST be stronger (as deemed by the responder) than any one of the authentication contexts
	// specified.
	ComparsionMax Comparison = "maximum"

	// ComparisonBetter requires that the resulting authentication context in the authentication
	// statement MUST be as strong as possible (as deemed by the responder) without exceeding the strength
	// of at least one of the authentication contexts specified.
	ComparisonBetter Comparison = "better"
)

// RequestedAuthnContext specifies the authentication context requirements of
// authentication statements returned in response to a request or query.
// See 3.3.2.2.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type RequestedAuthnContext struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`

	AuthnConextClassRef []string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	Comparison          Comparison `xml:",attr"`
}

type Extensions struct{}

// CreateDocument creates an AuthnRequest XML document.
func (a *AuthnRequest) CreateXMLDocument(indent int) ([]byte, error) {
	return xml.MarshalIndent(a, "", strings.Repeat("", indent))
}
