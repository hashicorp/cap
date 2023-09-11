package metadata

import (
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig/types"

	"github.com/hashicorp/cap/saml/models/core"
)

type ContactType string

const (
	ContactTypeTechnical      ContactType = "technical"
	ContactTypeSupport        ContactType = "support"
	ContactTypeAdministrative ContactType = "administrative"
	ContactTypeBilling        ContactType = "billing"
	ContactTypeOther          ContactType = "other"
)

type ProtocolSupportEnumeration string

const (
	ProtocolSupportEnumerationProtocol ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// KeyType defines what the key is used for.
// Possible values are "encryption" and "signing".
// See 2.4.1.1 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type KeyType string

const (
	KeyTypeEncryption KeyType = "encryption"
	KeyTypeSigning    KeyType = "signing"
)

// DescriptorCommon defines common fields used in Entity- and EntitiesDescriptor.
type DescriptorCommon struct {
	ID            string     `xml:",attr,omitempty"`
	ValidUntil    *time.Time `xml:"validUntil,attr,omitempty"`
	CacheDuration *Duration  `xml:"cacheDuration,attr,omitempty"`
	Signature     *dsig.Signature
}

// EntitiesDescriptor is a container that wraps one or more elements of
// EntityDiscriptor.
// See 2.3.1 in http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type EntitiesDescriptor struct {
	DescriptorCommon

	Name string

	EntitiesDescriptor []*EntitiesDescriptor
	EntityDescriptor   []*EntityDescriptor
}

// EntityDescriptor represents a system entity (IdP or SP) in metadata.
// See 2.3.2 in http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type EntityDescriptor struct {
	DescriptorCommon

	EntityID string `xml:"entityID,attr"`

	AffiliationDescriptor      *AffiliationDescriptor
	Organization               *Organization
	ContactPerson              *ContactPerson
	AdditionalMetadataLocation []string
}

// Organization specifies basic information about an organization responsible for a SAML
// entity or role.
// See 2.3.2.1 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type Organization struct {
	Extensions              []*etree.Element
	OrganizationName        []Localized
	OrganizationDisplayName []Localized
	OrganizationURL         []Localized
}

// ContactPerson  specifies basic contact information about a person responsible in some
// capacity for a SAML entity or role.
// See 2.3.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type ContactPerson struct {
	ContactType     ContactType `xml:",attr"`
	Extensions      []*etree.Element
	Company         string
	GivenName       string
	SurName         string
	EmailAddress    []string
	TelephoneNumber []string
}

// RoleDescriptor is an abstract extension point that contains common descriptive
// information intended to provide processing commonality across different roles.
// See 2.4.1 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type RoleDescriptor struct {
	DescriptorCommon

	ProtocolSupportEnumeration ProtocolSupportEnumeration `xml:"protocolSupportEnumeration,attr,omitempty"`
	ErrorURL                   string                     `xml:"errorURL,attr,omitempty"`
	KeyDescriptor              []KeyDescriptor
	Organization               *Organization
	ContactPerson              []ContactPerson
}

// KeyDescriptor  provides information about the cryptographic key(s) that an entity uses
// to sign data or receive encrypted keys, along with additional cryptographic details.
// See 2.4.1.1 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type KeyDescriptor struct {
	Use              KeyType `xml:"use,attr"`
	KeyInfo          KeyInfo
	EncryptionMethod []EncryptionMethod
}

// KeyInfo directly or indireclty identifies a key. It defines the usage of the
// XML Signature <ds:KeyInfo> element.
// See https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfo
type KeyInfo struct {
	dsig.KeyInfo
	KeyName string
}

// EncyrptionMethod describes the encryption algorithm applied to the cipher data.
// See https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-EncryptionMethod
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// SSODescriptor is the common base type for concrete types such as
// IDPSSODescriptor and SPSSODescriptor.
// See 2.4.2 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type SSODescriptor struct {
	RoleDescriptor

	ArtifactResolutionService []IndexedEndpoint
	SingleLogoutService       []Endpoint
	ManageNameIDService       []Endpoint
	NameIDFormat              []core.NameIDFormat
}

// AuthnAuthorityDescriptor ... ??? TODO
// See 2.4.5 http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
type AuthnAuthorityDescriptor struct {
	RoleDescriptor

	AuthnQueryService         []Endpoint
	AssertionIDRequestService []Endpoint
	NameIDFormats             []core.NameIDFormat
}

type PDPDescriptor struct {
}

// AttributeAuthorityDescriptor is a compatibiity requirement
// for supporting legacy or other SPs that rely on queries for
// attributes.
type AttributeAuthorityDescriptor struct {
}

// AffiliationDescriptor represents a group of other
// entitites, such as related service providers that
// share a persistent NameID.
type AffiliationDescriptor struct {
}

// X509Data contains one ore more identifiers of keys or X509 certifactes.
// See https://www.w3.org/TR/xmldsig-core1/#sec-X509Data
// type X509Data struct {
// 	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
// 	Data    string   `xml:",chardata"`
// }
