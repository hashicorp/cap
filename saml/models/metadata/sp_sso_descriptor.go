package metadata

import "encoding/xml"

// EntityDescriptorSPSSO defines an EntityDescriptor type
// that can accommodate an SPSSODescriptor.
// This type can be usued specifically to describe SPSSO profiles.
type EntityDescriptorSPSSO struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`

	entityDescriptor

	SPSSODescriptor []*SPSSODescriptor
}

// SPSSODescriptor contains profiles specific to service providers.
// It extends the SSODescriptor type.
// See 2.4.4 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type SPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`

	SSODescriptor

	AuthnRequestsSigned       bool `xml:",attr"`
	WantAssertionsSigned      bool `xml:",attr"`
	AssertionConsumerService  []IndexedEndpoint
	AttributeConsumingService []*AttributeConsumingService
	Attribute                 []Attribute
}

// AttributeConsumingService (ACS) is the location where an IdP will eventually send
// the user at the SP.
// See 2.4.4.1 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type AttributeConsumingService struct {
	Index              int  `xml:",attr"`
	IsDefault          bool `xml:"isDefault,attr"`
	ServiceName        []Localized
	ServiceDescription []Localized
	RequestedAttribute []RequestedAttribute
}

// RequestedAttribute specifies a service providers interest in a specific
// SAML attribute, including specific values.
// See 2.4.4.2 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type RequestedAttribute struct {
	Attribute
	IsRequired bool `xml:"isRequired,attr"`
}

// TODO: CORE This needs to be part of core?
type Attribute struct {
	FriendlyName   string `xml:",attr"`
	Name           string `xml:",attr"`
	NameFormat     string `xml:",attr"`
	AttributeValue []AttributeValue
}

// TODO: CORE
type AttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *NameID
}

// TODO: CORE
type NameID struct {
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Format          string `xml:",attr"`
	SPProvidedID    string `xml:",attr"`
	Value           string `xml:",chardata"`
}
