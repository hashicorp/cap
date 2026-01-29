// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"encoding/xml"
	"time"

	"github.com/crewjam/go-xmlsec/xmlenc"
)

const (
	SAMLVersion2 = "2.0"
)

type ServiceBinding string

const (
	ServiceBindingHTTPPost     ServiceBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	ServiceBindingHTTPRedirect ServiceBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	ServiceBindingSOAP         ServiceBinding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// See 8.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDFormat string

const (
	// See 8.3.1 - 8.3.8 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
	NameIDFormatUnspecified                NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmail                      NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatX509SubjectName            NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
	NameIDFormatWindowsDomainQualifiedName NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
	NameIDFormatKerberos                   NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
	NameIDFormatEntity                     NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	NameIDFormatPersistent                 NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient                  NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

type NameFormat string

const (
	NameFormatURI NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
)

// StatusCodeType defines the possible status codes in a SAML Response.
// The possible status codes are defined in:
// 3.2.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCodeType string

const (
	// StatusCodeSuccess indicates that the request succeeded.
	StatusCodeSuccess StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:Success"

	// StatusCodeRequester indicates that the request could not be performed due to
	// an error on the part of the requester.
	StatusCodeRequester StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	// StatusCodeResponder indicatest that the request could not be performed due to
	// an error on the part of the SAML responder or SAML authority.
	StatusCodeResponder StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	// StatusCodeVersionMismatch indicates that the SAML responder could not process the
	// request because the version of the request message was incorrect.
	StatusCodeVersionMismatch StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

	// StatusCodeAuthnFailed indicates that the responding provider was unable to successfully
	// authenticate the principal.
	StatusCodeAuthnFailed StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// StatusCodeInvalidAttrNameOrValue indicates that an unexpected or invalid content was
	// encountered within a <saml:Attribute> or <saml:AttributeValue> element.
	StatusCodeInvalidAttrNameOrValue StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

	// StatusCodeInvalidNameIDPolicy indicates that the responding provider cannot or will not support the
	// requested name identifier policy.
	StatusCodeInvalidNameIDPolicy StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

	// StatusCodeNoAuthnContext indicates that the specified authentication context requirements cannot
	// be met by the responder.
	StatusCodeNoAuthnContext StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

	// StatusCodeNoAvailableIDP indicates that the Used by an intermediary to indicate that none of the
	// supported identity provider <Loc> elements in an <IDPList> can be resolved or that none of the
	// supported identity providers are available.
	StatusCodeNoAvailableIDP StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

	// StatusCodeNoPassive indicates that the responding provider cannot authenticate the principal passively,
	// as has been requested.
	StatusCodeNoPassive StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"

	// StatusCodeNoSupportedIDP is used by an intermediary to indicate that none of the identity providers in an
	// <IDPList> are supported by the intermediary.
	StatusCodeNoSupportedIDP StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

	// StatusCodePartialLogout is used by a session authority to indicate to a session participant that it
	// was not able to propagate logout to all other session participants.
	StatusCodePartialLogout StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	// StatusCodeProxyCountExceeded indicates that a responding provider cannot authenticate the principal
	// directly and is not permitted to proxy the request further.
	StatusCodeProxyCountExceeded StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

	// StatusCodeRequestDenied indicates that the SAML responder or SAML authority is able to process the
	// request but has chosen not to respond. This status code MAY be used when there is concern about the
	// security context of the request message or the sequence of request messages received from a particular
	// requester.
	StatusCodeRequestDenied StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

	// StatusCodeRequestUnsupported indicates that the SAML responder or SAML authority does not support the
	// request.
	StatusCodeRequestUnsupported StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

	// StatusCodeRequestVersionDeprecated indicates that the SAML responder cannot process any requests with
	// the protocol version specified in the request.
	StatusCodeRequestVersionDeprecated StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"

	// StatusCodeRequestRequestVersionTooHigh indicates that the SAML responder cannot process the request because
	// the protocol version specified in the request message is a major upgrade from the highest protocol version
	// supported by the responder.
	StatusCodeRequestRequestVersionTooHigh StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"

	// StatusCodeRequestRequestVersionTooLow indicates that the SAML responder cannot process the request because
	// the protocol version specified in the request message is too low.
	StatusCodeRequestVersionTooLow StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

	// StatusCodeRequestResourceNotRecognized indicates that the resource value provided in the request message is
	// invalid or unrecognized.
	StatusCodeResourceNotRecognized StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

	// StatusCodeTooManyResponses indicates that the response message would contain more elements than the SAML
	// responder is able to return.
	StatusCodeTooManyResponses StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

	// StatusCodeUnknownAttrProfile indicates that an entity that has no knowledge of a particular attribute
	// profile has been presented with an attribute drawn from that profile.
	StatusCodeUnknownAttrProfile StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

	// StatusCodeUnknownPrincipal indicates that the responding provider does not recognize the principal
	// specified or implied by the request.
	StatusCodeUnknownPrincipal StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

	// StatusCodeUnsupportedBinding indicates that the SAML responder cannot properly fulfill the request using
	// the protocol binding specified in the request.
	StatusCodeUnsupportedBinding StatusCodeType = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

// ConfirmationMethod indicates the sepcific method to be used by the relying parte to determine
// that the request or message came from a system entity that is associated with the subject of
// the assertion, within the context of a particular profile.
//
// See 3. http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
type ConfirmationMethod string

const (
	// ConfirmationMethodHolderOfKey indicates that the key holder itself can confirm
	// itself as the subject. If this method is given, the SubjectConfirmationData MUST
	// contain one or more KeyInfo elements, where KeyInfo identifies a cryptographic key.
	//
	// See 3.1 http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
	ConfirmationMethodHolderOfKey ConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

	// ConfirmationMethodSenderVouches indicates that no other information is available about
	// the context of use of the assertion.
	//
	// See 3.2 http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
	ConfirmationMethodSenderVouches ConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"

	// ConfirmationMethodBearer indicates that the bearer can confirm itself as the subject.
	//
	// See 3.3 http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
	ConfirmationMethodBearer ConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// See 3.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type RequestResponseCommon struct {
	ID      string `xml:",attr"` // required
	Version string `xml:",attr"` // required

	// The time instant of issue of the request.
	IssueInstant time.Time   `xml:",attr"`           // required
	Consent      string      `xml:",attr,omitempty"` // optional TODO: define constants
	Issuer       *Issuer     // recommended
	Singature    string      `xml:",omitempty"` // recommended
	Extensions   *Extensions // optional
	Destination  string      `xml:",attr"`
}

// See 2.2.1 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type BaseID struct {
	NameQualifier   string `xml:",attr,omitempty"`
	SPNameQualifier string `xml:",attr,omitempty"`
}

// See 2.2.2 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDType struct {
	NameQualifier   string       `xml:",attr,omitempty"`
	SPNameQualifier string       `xml:",attr,omitempty"`
	Format          NameIDFormat `xml:",attr,omitempty"`
	SPProvidedID    string       `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

// See 2.2.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameID = NameIDType

// See 2.2.3 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type EncryptedID struct {
	EncryptedData xmlenc.EncryptedData
	EncryptedKey  xmlenc.EncryptedKey
}

// Issuer, with type NameIDType, provides information about the issuer of a SAML assertion.
// See 2.2.5 http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	NameIDType
}

// Indicates that an attribute is yet to be defined.
// It is only used to for development purposes.
type TBD struct{}
