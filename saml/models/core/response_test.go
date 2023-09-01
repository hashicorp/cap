package core_test

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
)

var ResponseXMLSignature = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
         <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
         <ds:Reference URI="#_03a4084d93f8df3cf3caf21878f20c08">
            <ds:Transforms>
               <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
               <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                  <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xsd" />
               </ds:Transform>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <ds:DigestValue>Hs5IUzabpy3X7gqpi0FbyGQoqgVaNwfAQvHymdEHJtE=</ds:DigestValue>
         </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>jgRgXKmIhn/OGcScnKC2zkg/kIEnThE8CzxqkG1cM2UHgkjB+zB2CkxJ/TmjYL+qljjJmeijgkabwhiDMwVJ62tEYv2Ck5OliRyF2mvO+lV0XIFjbXIvJm20R3xP3US23Vj6UpFX/kqlgD//K/v8uS4KENVok0UCQgqXT8JtDTCSmg6aV+boE8KrgFsKXX75zH7ZpUDOIDakmNXDXsS/y7xTtu23YNHLCiP99Px22kJ+cDk30I7/w2DN85si6dvmfbV4jSwFQHyf4ZT6RRk0TkOjTCEkN6qDdEOsbUPDYurUXeDUD2WU2YMCE0JDaymPedh1JtNoQS64UQssjTduFA==</ds:SignatureValue>
      <ds:KeyInfo>
         <ds:X509Data>
            <ds:X509Certificate>MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEBCwUAMBYxFDAS BgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4MDgyNDIxMTQwOVowFjEUMBIG A1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFK s71ufbQwoQoW7qkNAJRIANGA4iM0ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyj xj0uJ4lArgkr4AOEjj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVN c1klbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF/cL5fOpd Va54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8nspXiH/MZW8o2cqWRkrw3 MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0GA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE 4k2ZNTA0BgNVHREELTArggtzYW1sdGVzdC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lk cDANBgkqhkiG9w0BAQsFAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3 YaMb2RSn7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHTTNiL ArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nblD1JJKSQ3AdhxK/we P3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcUZOpx4swtgGdeoSpeRyrtMvRwdcci NBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==</ds:X509Certificate>
         </ds:X509Data>
      </ds:KeyInfo>
   </ds:Signature>
</saml2p:Response>`

var responseXMLContainer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
</saml2p:Response>`

func Test_ParseResponse_ResponseContainer(t *testing.T) {
	r := require.New(t)

	res := responseXML(t, responseXMLContainer)

	r.Equal(res.Destination, "http://localhost:8000/saml/acs")
	r.Equal(res.ID, "saml-response-id")
	r.Equal(res.InResponseTo, "saml-request-id")
	r.Equal(res.IssueInstant.String(), "2023-03-31 06:55:44.494 +0000 UTC")
	r.Equal(res.Version, "2.0")
}

var responseXMLIssuer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://samltest.id/saml/idp</saml2:Issuer>
</saml2p:Response>`

func Test_ParseResponse_Issuer(t *testing.T) {
	r := require.New(t)

	iss := responseXML(t, responseXMLIssuer).Issuer

	r.Equal(iss.Value, "https://samltest.id/saml/idp")
}

var responseXMLStatus = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   <saml2p:Status>
      <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
   </saml2p:Status>
</saml2p:Response>`

var responseXMLAssertion = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   </saml2:Assertion>
</saml2p:Response>`

func Test_ParseResponse_Assertion(t *testing.T) {
	r := require.New(t)

	assert := responseXML(t, responseXMLAssertion).Assertion[0]

	r.Equal("assertion-id", assert.ID)
	r.Equal("2023-03-31 06:55:44.494 +0000 UTC", assert.IssueInstant.String())
	r.Equal("2.0", assert.Version)

}

var responseXMLAssertionIssuer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
      <saml2:Issuer>https://samltest.id/saml/idp</saml2:Issuer>
   </saml2:Assertion>
</saml2p:Response>`

func Test_ParseResponse_Assertion_Issuer(t *testing.T) {
	r := require.New(t)

	iss := responseXML(t, responseXMLAssertionIssuer).Assertion[0].Issuer

	r.Equal("https://samltest.id/saml/idp", iss.Value)
}

var responseXMLAssertionSubject = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_e640115ff8cb660afcc64dcc5d1b5849" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
      <saml2:Subject>
         <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="https://samltest.id/saml/idp" SPNameQualifier="http://saml.test/example">someone@samltest.id</saml2:NameID>
         <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData Address="1.2.3.4" InResponseTo="request-id" NotOnOrAfter="2023-03-31T07:00:44.509Z" Recipient="http://localhost:8000/saml/acs" />
         </saml2:SubjectConfirmation>
      </saml2:Subject>
   </saml2:Assertion>
</saml2p:Response>`

func Test_ParseResponse_Assertion_Subject(t *testing.T) {
	r := require.New(t)

	sub := responseXML(t, responseXMLAssertionSubject).Assertion[0].Subject

	r.Equal(core.NameIDFormatEmail, sub.NameID.Format)
	r.Equal("https://samltest.id/saml/idp", sub.NameID.NameQualifier)
	r.Equal("http://saml.test/example", sub.NameID.SPNameQualifier)
	r.Equal("someone@samltest.id", sub.NameID.Value)
	r.Equal(core.ConfirmationMethodBearer, sub.SubjectConfirmation[0].Method)
	r.Equal("1.2.3.4", sub.SubjectConfirmation[0].SubjectConfirmationData.Address)
	r.Equal("request-id", sub.SubjectConfirmation[0].SubjectConfirmationData.InResponseTo)
}

var responseXMLAssertions = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_e640115ff8cb660afcc64dcc5d1b5849" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
      <saml2:Issuer>https://samltest.id/saml/idp</saml2:Issuer>
      <saml2:Subject>
         <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" NameQualifier="https://samltest.id/saml/idp" SPNameQualifier="http://saml.julz/example">rsanchez@samltest.id</saml2:NameID>
         <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData Address="80.140.197.138" InResponseTo="08aef46c-69f5-bd8e-2e57-3cb0dd4682b6" NotOnOrAfter="2023-03-31T07:00:44.509Z" Recipient="http://localhost:8000/saml/acs" />
         </saml2:SubjectConfirmation>
      </saml2:Subject>
      <saml2:Conditions NotBefore="2023-03-31T06:55:44.494Z" NotOnOrAfter="2023-03-31T07:00:44.494Z">
         <saml2:AudienceRestriction>
            <saml2:Audience>http://saml.julz/example</saml2:Audience>
         </saml2:AudienceRestriction>
      </saml2:Conditions>
      <saml2:AuthnStatement AuthnInstant="2023-03-31T06:55:41.139Z" SessionIndex="_590baa6b9534066a50f9cc50baa928e1">
         <saml2:SubjectLocality Address="80.140.197.138" />
         <saml2:AuthnContext>
            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
         </saml2:AuthnContext>
      </saml2:AuthnStatement>
      <saml2:AttributeStatement>
         <saml2:Attribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>urn:mace:dir:entitlement:common-lib-terms</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>rick</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">rsanchez@samltest.id</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>+1-555-555-5515</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="role" Name="https://samltest.id/attributes/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">manager@Samltest.id</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>rsanchez@samltest.id</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>Sanchez</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>Rick Sanchez</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>Rick</saml2:AttributeValue>
         </saml2:Attribute>
      </saml2:AttributeStatement>
   </saml2:Assertion>
</saml2p:Response>`

func responseXML(t *testing.T, ssoRes string) core.ResponseOld {
	t.Helper()

	r := require.New(t)

	res := core.ResponseOld{}

	err := xml.Unmarshal([]byte(ssoRes), &res)
	r.NoError(err)

	return res
}
