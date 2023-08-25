package metadata_test

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

var exampleSPSSODescriptorA = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://hashicorp.com/SAML">
   <ds:Signature>signature</ds:Signature>
   <SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
         <ds:KeyInfo>
            <ds:KeyName>ServiceProvider.com SSO Key</ds:KeyName>
         </ds:KeyInfo>
      </KeyDescriptor>
      <KeyDescriptor use="encryption">
         <ds:KeyInfo>
            <ds:KeyName>ServiceProvider.com Encrypt Key</ds:KeyName>
         </ds:KeyInfo>
         <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa1_5" />
      </KeyDescriptor>
      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://ServiceProvider.com/SAML/SLO/SOAP" />
      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://ServiceProvider.com/SAML/SLO/Browser" ResponseLocation="https://ServiceProvider.com/SAML/SLO/Response" />
      <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
      <AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://ServiceProvider.com/SAML/SSO/Artifact" />
      <AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://ServiceProvider.com/SAML/SSO/POST" />
      <AttributeConsumingService index="0">
         <ServiceName xml:lang="en">Academic Journals R US</ServiceName>
         <RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" FriendlyName="eduPersonEntitlement">
            <saml:AttributeValue>https://ServiceProvider.com/entitlements/123456789</saml:AttributeValue>
         </RequestedAttribute>
      </AttributeConsumingService>
   </SPSSODescriptor>
   <Organization>
      <OrganizationName xml:lang="en">Academic Journals R US</OrganizationName>
      <OrganizationDisplayName xml:lang="en">Academic Journals R US, a Division of Dirk Corp.</OrganizationDisplayName>
      <OrganizationURL xml:lang="en">https://ServiceProvider.com</OrganizationURL>
   </Organization>
</EntityDescriptor>`

var exampleSPSSODescriptor = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
    <SPSSODescriptor
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true"
        protocolSupportEnumeration=
            "urn:oasis:names:tc:SAML:2.0:protocol">
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleSPSSODescriptor), ed)
	r.NoError(err)

	r.Len(ed.SPSSODescriptor, 1)

	spSSO := ed.SPSSODescriptor[0]

	r.True(spSSO.AuthnRequestsSigned)
	r.True(spSSO.WantAssertionsSigned)
	r.Equal(spSSO.ProtocolSupportEnumeration, metadata.ProtocolSupportEnumerationProtocol)
}

var exampleSLOService = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
    <SPSSODescriptor
        protocolSupportEnumeration=
            "urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://hashicorp.com/slo/endpoint"
            ResponseLocation="https://hashicorp.com/slo/endpoint"/>
        <SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
            Location="https://hashicorp.com/slo/endpoint"/>
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor_SLOService(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleSLOService), ed)
	r.NoError(err)

	slo := ed.SPSSODescriptor[0].SingleLogoutService

	r.Len(slo, 2)

	r.Equal(slo[0].Binding, core.ServiceBindingHTTPRedirect)
	r.Equal(slo[0].Location, "https://hashicorp.com/slo/endpoint")
	r.Equal(slo[0].ResponseLocation, "https://hashicorp.com/slo/endpoint")

	r.Equal(slo[1].Binding, core.ServiceBindingSOAP)
	r.Equal(slo[1].Location, "https://hashicorp.com/slo/endpoint")
	r.Equal(slo[1].ResponseLocation, "")
}

var exampleNameIDService = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
     <SPSSODescriptor
         AuthnRequestsSigned="true"
         WantAssertionsSigned="true"
         protocolSupportEnumeration=
             "urn:oasis:names:tc:SAML:2.0:protocol">
         <ManageNameIDService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://hashicorp.com/nameid/endpoint"
            ResponseLocation="https://hashicorp.com/nameid/endpoint"/>
         <ManageNameIDService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
            Location="https://hashicorp.com/nameid/endpoint"
            ResponseLocation="https://hashicorp.com/nameid/endpoint"/>
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor_ManageNameIDService(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleNameIDService), ed)
	r.NoError(err)

	nameIDSvc := ed.SPSSODescriptor[0].ManageNameIDService

	r.Len(nameIDSvc, 2)

	r.Equal(nameIDSvc[0].Binding, core.ServiceBindingHTTPRedirect)
	r.Equal(nameIDSvc[0].Location, "https://hashicorp.com/nameid/endpoint")
	r.Equal(nameIDSvc[0].ResponseLocation, "https://hashicorp.com/nameid/endpoint")

	r.Equal(nameIDSvc[1].Binding, core.ServiceBindingSOAP)
	r.Equal(nameIDSvc[1].Location, "https://hashicorp.com/nameid/endpoint")
	r.Equal(nameIDSvc[1].ResponseLocation, "https://hashicorp.com/nameid/endpoint")
}

var exampleNameIDFormats = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
	<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor_NameIDFormats(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleNameIDFormats), ed)
	r.NoError(err)

	nameIDFormats := ed.SPSSODescriptor[0].NameIDFormat

	r.Len(nameIDFormats, 3)

	r.Equal(nameIDFormats[0], core.NameIDFormatPersistent)
	r.Equal(nameIDFormats[1], core.NameIDFormatEmail)
	r.Equal(nameIDFormats[2], core.NameIDFormatTransient)
}

var exampleACS = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService
            isDefault="true"
            index="0"
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://hashicorp.com/acs/endpoint"/>
        <AssertionConsumerService
            index="1"
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://hashicorp.com/acs/endpoint"/>
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor_ACS(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleACS), ed)
	r.NoError(err)

	acs := ed.SPSSODescriptor[0].AssertionConsumerService

	r.Len(acs, 2)

	r.True(acs[0].IsDefault)
	r.Equal(acs[0].Binding, core.ServiceBindingHTTPRedirect)
	r.Equal(acs[0].Index, 0)
	r.Equal(acs[0].Location, "https://hashicorp.com/acs/endpoint")

	r.False(acs[1].IsDefault)
	r.Equal(acs[1].Binding, core.ServiceBindingHTTPPost)
	r.Equal(acs[1].Index, 1)
	r.Equal(acs[1].Location, "https://hashicorp.com/acs/endpoint")
}

var exampleAttributeConsumingService = `<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="hashicorp.com">
    <SPSSODescriptor
        protocolSupportEnumeration=
            "urn:oasis:names:tc:SAML:2.0:protocol">
      <AttributeConsumingService index="0" isDefault="true">
         <ServiceName xml:lang="en">Academic Journals R US</ServiceName>
         <ServiceName xml:lang="de">Wir sind Akademische Zeitungen</ServiceName>
         <RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	    Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
	    FriendlyName="eduPersonEntitlement"
	    isRequired="true">
              <saml:AttributeValue>https://hashicorp.com/entitlements/123456789</saml:AttributeValue>
         </RequestedAttribute>
      </AttributeConsumingService>
      <AttributeConsumingService index="1">
         <ServiceName xml:lang="en">Academic Journals R US</ServiceName>
         <RequestedAttribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	    Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.8"
	    FriendlyName="eduPersonEntitlement">
              <saml:AttributeValue>https://hashicorp.com/entitlements/987654321</saml:AttributeValue>
         </RequestedAttribute>
      </AttributeConsumingService>
    </SPSSODescriptor>
</EntityDescriptor>`

// TODO: Check on Attributes & AttributeValues
// <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
// Name="FirstName">
// <saml:AttributeValue xsi:type="xs:string">By-Tor</saml:AttributeValue>
// </saml:Attribute>
// <saml:AttributeValue type="xs:string">By-Tor</saml:AttributeValue>

func Test_SPSSODescriptor_AttributeConsumingService(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptorSPSSO{}

	err := xml.Unmarshal([]byte(exampleAttributeConsumingService), ed)
	r.NoError(err)

	acs := ed.SPSSODescriptor[0].AttributeConsumingService

	r.Len(acs, 2)

	r.Equal(acs[0].Index, 0)
	r.True(acs[0].IsDefault)

	r.Equal(acs[0].ServiceName[0].Lang, "en")
	r.Equal(acs[0].ServiceName[0].Value, "Academic Journals R US")
	r.Equal(acs[0].ServiceName[1].Lang, "de")
	r.Equal(acs[0].ServiceName[1].Value, "Wir sind Akademische Zeitungen")

	r.Equal(acs[0].RequestedAttribute[0].Name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.7")
	r.Equal(acs[0].RequestedAttribute[0].FriendlyName, "eduPersonEntitlement")
	r.Equal(acs[0].RequestedAttribute[0].NameFormat, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	r.True(acs[0].RequestedAttribute[0].IsRequired)
	r.Len(acs[0].RequestedAttribute[0].AttributeValue, 1)
	r.Equal(acs[0].RequestedAttribute[0].AttributeValue[0].Value, "https://hashicorp.com/entitlements/123456789")

	r.Equal(acs[1].ServiceName[0].Lang, "en")
	r.Equal(acs[1].ServiceName[0].Value, "Academic Journals R US")

	r.Equal(acs[1].RequestedAttribute[0].Name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.8")
	r.Equal(acs[1].RequestedAttribute[0].FriendlyName, "eduPersonEntitlement")
	r.Equal(acs[1].RequestedAttribute[0].NameFormat, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	r.Len(acs[1].RequestedAttribute[0].AttributeValue, 1)
	r.Equal(acs[1].RequestedAttribute[0].AttributeValue[0].Value, "https://hashicorp.com/entitlements/987654321")
}

var exampleKeyDescriptor = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
MIICYDCCAgqgAwIBAgICBoowDQYJKoZIhvcNAQEEBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRQwEgYDVQQHEwtTYW50YSBDbGFyYTEeMBwGA1UEChMVU3VuIE1pY3Jvc3lz
dGVtcyBJbmMuMRowGAYDVQQLExFJZGVudGl0eSBTZXJ2aWNlczEcMBoGA1UEAxMTQ2VydGlmaWNh
dGUgTWFuYWdlcjAeFw0wNjExMDIxOTExMzRaFw0xMDA3MjkxOTExMzRaMDcxEjAQBgNVBAoTCXNp
cm9lLmNvbTEhMB8GA1UEAxMYbG9hZGJhbGFuY2VyLTkuc2lyb2UuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCjOwa5qoaUuVnknqf5pdgAJSEoWlvx/jnUYbkSDpXLzraEiy2UhvwpoBgB
EeTSUaPPBvboCItchakPI6Z/aFdH3Wmjuij9XD8r1C+q//7sUO0IGn0ORycddHhoo0aSdnnxGf9V
tREaqKm9dJ7Yn7kQHjo2eryMgYxtr/Z5Il5F+wIDAQABo2AwXjARBglghkgBhvhCAQEEBAMCBkAw
DgYDVR0PAQH/BAQDAgTwMB8GA1UdIwQYMBaAFDugITflTCfsWyNLTXDl7cMDUKuuMBgGA1UdEQQR
MA+BDW1hbGxhQHN1bi5jb20wDQYJKoZIhvcNAQEEBQADQQB/6DOB6sRqCZu2OenM9eQR0gube85e
nTTxU4a7x1naFxzYXK1iQ1vMARKMjDb19QEJIEJKZlDK4uS7yMlf1nFS
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
MIICTDCCAfagAwIBAgICBo8wDQYJKoZIhvcNAQEEBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRQwEgYDVQQHEwtTYW50YSBDbGFyYTEeMBwGA1UEChMVU3VuIE1pY3Jvc3lz
dGVtcyBJbmMuMRowGAYDVQQLExFJZGVudGl0eSBTZXJ2aWNlczEcMBoGA1UEAxMTQ2VydGlmaWNh
dGUgTWFuYWdlcjAeFw0wNjExMDcyMzU2MTdaFw0xMDA4MDMyMzU2MTdaMCMxITAfBgNVBAMTGGxv
YWRiYWxhbmNlci05LnNpcm9lLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAw574iRU6
HsSO4LXW/OGTXyfsbGv6XRVOoy3v+J1pZ51KKejcDjDJXNkKGn3/356AwIaqbcymWd59T0zSqYfR
Hn+45uyjYxRBmVJseLpVnOXLub9jsjULfGx0yjH4w+KsZSZCXatoCHbj/RJtkzuZY6V9to/hkH3S
InQB4a3UAgMCAwEAAaNgMF4wEQYJYIZIAYb4QgEBBAQDAgZAMA4GA1UdDwEB/wQEAwIE8DAfBgNV
HSMEGDAWgBQ7oCE35Uwn7FsjS01w5e3DA1CrrjAYBgNVHREEETAPgQ1tYWxsYUBzdW4uY29tMA0G
CSqGSIb3DQEBBAUAA0EAMlbfBg/ff0Xkv4DOR5LEqmfTZKqgdlD81cXynfzlF7XfnOqI6hPIA90I
x5Ql0ejivIJAYcMGUyA+/YwJg2FGoA==
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
            <EncryptionMethod Algorithm=
                "https://www.w3.org/2001/04/xmlenc#aes128-cbc">
                <KeySize xmlns="https://www.w3.org/2001/04/xmlenc#">128</KeySize>
            </EncryptionMethod>
        </KeyDescriptor>
    </SPSSODescriptor>
</EntityDescriptor>`

func Test_SPSSODescriptor_KeyDescritpor(t *testing.T) {
	r := require.New(t)

	ed := &metadata.EntityDescriptor{}

	err := xml.Unmarshal([]byte(exampleKeyDescriptor), ed)
	r.NoError(err)

	// keyDescriptor := ed.SPSSODescriptor[0].KeyDescriptor

	// r.Len(keyDescriptor, 2)

	// r.Equal(keyDescriptor[0].Use, metadata.KeyTypeSigning)
	// r.NotEmpty(keyDescriptor[0].KeyInfo.X509Data, "")

	// r.Equal(keyDescriptor[1].Use, metadata.KeyTypeEncryption)
	// r.NotEmpty(keyDescriptor[1].KeyInfo.X509Data, "")
}
