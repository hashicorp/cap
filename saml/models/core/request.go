package core

import (
	"encoding/xml"
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
	NameIDPolicy         *NameIDPolicy
	Conditions           *Conditions
	RequestedAuthContext *RequestedAuthContext
	Scoping              *Scoping

	ForceAuthn bool `xml:",attr"`
	IsPassive  bool `xml:",attr"`

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
// See 2.4.1.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	Format          NameIDFormat
	SPNameQualifier string `xml:",attr,omitempty"`
	AllowCreate     bool   `xml:",attr"`
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

type Conditions struct {
}

type RequestedAuthContext struct {
}

type Extensions struct {
}

// CreateDocument creates an AuthnRequest XML document.
func (a *AuthnRequest) CreateXMLDocument() ([]byte, error) {
	return xml.Marshal(a)
}
