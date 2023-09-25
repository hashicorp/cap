// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package core_test

import (
	"encoding/xml"
	"testing"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/stretchr/testify/require"
)

func TestResponse(t *testing.T) {
	tests := []struct {
		name        string
		responseXML string
		assertions  func(*testing.T, core.Response)
	}{
		{
			name:        "response container",
			responseXML: responseXMLContainer,
			assertions: func(t *testing.T, response core.Response) {
				require.Equal(t, response.Destination, "http://localhost:8000/saml/acs")
				require.Equal(t, response.ID, "saml-response-id")
				require.Equal(t, response.IssueInstant.String(), "2023-03-31 06:55:44.494 +0000 UTC")
				require.Equal(t, response.Version, "2.0")
			},
		},
		{
			name:        "assertions helper",
			responseXML: responseXMLAssertion,
			assertions: func(t *testing.T, response core.Response) {
				assertions := response.Assertions()
				require.Len(t, assertions, 1)
				assertion := assertions[0]

				require.Equal(t, "assertion-id", assertion.ID)
				require.Equal(t, "2023-03-31 06:55:44.494 +0000 UTC", assertion.IssueInstant.String())
				require.Equal(t, "2.0", assertion.Version)
			},
		},
		{
			name:        "assertion subject helper",
			responseXML: responseXMLAssertionSubject,
			assertions: func(t *testing.T, response core.Response) {
				assertions := response.Assertions()
				require.Len(t, assertions, 1)
				assertion := assertions[0]

				require.Equal(t, "someone@samltest.id", assertion.SubjectNameID())
				require.EqualValues(t, core.ConfirmationMethodBearer, assertion.Subject.SubjectConfirmation.Method)
				require.Equal(t, "http://localhost:8000/saml/acs", assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
				require.Equal(t, "request-id", assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo)
			},
		},
		{
			name:        "assertion issuer helper",
			responseXML: responseXMLAssertionIssuer,
			assertions: func(t *testing.T, response core.Response) {
				assertions := response.Assertions()
				require.Len(t, assertions, 1)
				assertion := assertions[0]

				require.Equal(t, "https://samltest.id/saml/idp", assertion.Issuer())
			},
		},
		{
			name:        "response issuer helper",
			responseXML: responseXMLIssuer,
			assertions: func(t *testing.T, response core.Response) {
				require.Equal(t, "https://samltest.id/saml/idp2", response.Issuer())
			},
		},
		{
			name:        "response status code",
			responseXML: responseXMLStatus,
			assertions: func(t *testing.T, response core.Response) {
				require.Equal(t, string(core.StatusCodeSuccess), response.Status.StatusCode.Value)
			},
		},
		{
			name:        "assertion attributes helper",
			responseXML: responseXMLAssertionAttributes,
			assertions: func(t *testing.T, response core.Response) {
				assertions := response.Assertions()
				require.Len(t, assertions, 1)
				assertion := assertions[0]
				attributes := assertion.Attributes()
				require.Len(t, attributes, 3)
				require.Equal(t, "telephoneNumber", attributes[0].FriendlyName)
				require.Equal(t, "+1-555-555-5555", attributes[0].Values[0].Value)
				require.Equal(t, "+1-777-777-7777", attributes[0].Values[1].Value)
				require.Equal(t, "email", attributes[1].FriendlyName)
				require.Equal(t, "rsanchez@samltest.id", attributes[1].Values[0].Value)
				require.Equal(t, "givenName", attributes[2].FriendlyName)
				require.Equal(t, "Rick", attributes[2].Values[0].Value)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			response := responseXML(t, tt.responseXML)
			tt.assertions(t, response)
		})
	}
}

func responseXML(t *testing.T, ssoRes string) core.Response {
	t.Helper()

	res := core.Response{}
	err := xml.Unmarshal([]byte(ssoRes), &res)
	require.NoError(t, err)
	return res
}

const (
	responseXMLContainer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
</saml2p:Response>`

	responseXMLIssuer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://samltest.id/saml/idp2</saml2:Issuer>
</saml2p:Response>`

	responseXMLStatus = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   <saml2p:Status>
      <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
   </saml2p:Status>
</saml2p:Response>`

	responseXMLAssertion = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
   </saml2:Assertion>
</saml2p:Response>`

	responseXMLAssertionIssuer = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
      <saml2:Issuer>https://samltest.id/saml/idp</saml2:Issuer>
   </saml2:Assertion>
</saml2p:Response>`

	responseXMLAssertionSubject = `<?xml version="1.0" encoding="UTF-8"?>
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

	responseXMLAssertionAttributes = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Destination="http://localhost:8000/saml/acs" ID="saml-response-id" InResponseTo="saml-request-id" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_e640115ff8cb660afcc64dcc5d1b5849" IssueInstant="2023-03-31T06:55:44.494Z" Version="2.0">
      <saml2:AttributeStatement>
         <saml2:Attribute FriendlyName="telephoneNumber" Name="urn:oid:2.5.4.20" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>+1-555-555-5555</saml2:AttributeValue>
            <saml2:AttributeValue>+1-777-777-7777</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="email" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>rsanchez@samltest.id</saml2:AttributeValue>
         </saml2:Attribute>
         <saml2:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml2:AttributeValue>Rick</saml2:AttributeValue>
         </saml2:Attribute>
      </saml2:AttributeStatement>
   </saml2:Assertion>
</saml2p:Response>`
)
