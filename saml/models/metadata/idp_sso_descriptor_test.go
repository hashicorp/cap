// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metadata_test

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

var exampleIDPSSODescriptorX = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <ds:Signature>...</ds:Signature>
   <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
         <ds:KeyInfo>
            <ds:KeyName>IdentityProvider.com AA Key</ds:KeyName>
         </ds:KeyInfo>
      </KeyDescriptor>
      <AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://IdentityProvider.com/SAML/AA/SOAP" />
      <AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:URI" Location="https://IdentityProvider.com/SAML/AA/URI" />
      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
      <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
      <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
      <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" />
      <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" FriendlyName="eduPersonAffiliation">
         <saml:AttributeValue>member</saml:AttributeValue>
         <saml:AttributeValue>student</saml:AttributeValue>
         <saml:AttributeValue>faculty</saml:AttributeValue>
         <saml:AttributeValue>employee</saml:AttributeValue>
         <saml:AttributeValue>staff</saml:AttributeValue>
      </saml:Attribute>
   </AttributeAuthorityDescriptor>
   <Organization>
      <OrganizationName xml:lang="en">Identity Providers R US</OrganizationName>
      <OrganizationDisplayName xml:lang="en">Identity Providers R US, a Division of Lerxst Corp.</OrganizationDisplayName>
      <OrganizationURL xml:lang="en">https://IdentityProvider.com</OrganizationURL>
   </Organization>
</EntityDescriptor>`

var exampleIDPSSODescriptor = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSODescriptor), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	idp := ed.IDPSSODescriptor[0]

	r.True(idp.WantAuthnRequestsSigned)
	r.Equal(idp.ProtocolSupportEnumeration, metadata.ProtocolSupportEnumerationProtocol)
}

var exampleIDPSSOKeyDescriptor = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
         <ds:KeyInfo>
            <ds:KeyName>IdentityProvider.com SSO Key</ds:KeyName>
         </ds:KeyInfo>
      </KeyDescriptor>
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor_KeyDescriptor(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSOKeyDescriptor), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	idp := ed.IDPSSODescriptor[0]

	r.Len(idp.KeyDescriptor, 1)
	r.Equal(idp.KeyDescriptor[0].Use, metadata.KeyTypeSigning)
	r.Equal(idp.KeyDescriptor[0].KeyInfo.KeyName, "IdentityProvider.com SSO Key")
}

var exampleIDPSSODescriptorArtifactResolutionService = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <ArtifactResolutionService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://hashicorp-idp.com/SAML/Artifact" />
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor_ArtifactResolutionService(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSODescriptorArtifactResolutionService), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	ars := ed.IDPSSODescriptor[0].ArtifactResolutionService

	r.Len(ars, 1)

	r.True(ars[0].IsDefault)
	r.Equal(ars[0].Index, 0)
	r.Equal(ars[0].Binding, core.ServiceBindingSOAP)
	r.Equal(ars[0].Location, "https://hashicorp-idp.com/SAML/Artifact")
}

var exampleIDPSSODescriptorSLO = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://hashicorp.com/SAML/SLO/SOAP" />
      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://hashicorp.com/SAML/SLO/Browser" ResponseLocation="https://IdentityProvider.com/SAML/SLO/Response" />
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor_SLO(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSODescriptorSLO), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	slo := ed.IDPSSODescriptor[0].SingleLogoutService

	r.Len(slo, 2)

	r.Equal(slo[0].Binding, core.ServiceBindingSOAP)
	r.Equal(slo[0].Location, "https://hashicorp.com/SAML/SLO/SOAP")

	r.Equal(slo[1].Binding, core.ServiceBindingHTTPRedirect)
	r.Equal(slo[1].Location, "https://hashicorp.com/SAML/SLO/Browser")
}

var exampleIDPSSODescriptorSSO = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://hashicorp.com/SAML/SSO/Browser" />
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://hashicorp.com/SAML/SSO/Browser" />
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor_SSO(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSODescriptorSSO), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	sso := ed.IDPSSODescriptor[0].SingleSignOnService

	r.Len(sso, 2)

	r.Equal(sso[0].Binding, core.ServiceBindingHTTPRedirect)
	r.Equal(sso[0].Location, "https://hashicorp.com/SAML/SSO/Browser")

	r.Equal(sso[1].Binding, core.ServiceBindingHTTPPost)
	r.Equal(sso[1].Location, "https://hashicorp.com/SAML/SSO/Browser")
}

var exampleIDPSSODescriptorAttributes = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://IdentityProvider.com/SAML">
   <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" />
      <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" FriendlyName="eduPersonAffiliation">
         <saml:AttributeValue>member</saml:AttributeValue>
         <saml:AttributeValue>student</saml:AttributeValue>
         <saml:AttributeValue>faculty</saml:AttributeValue>
         <saml:AttributeValue>employee</saml:AttributeValue>
         <saml:AttributeValue>staff</saml:AttributeValue>
      </saml:Attribute>
   </IDPSSODescriptor>
</EntityDescriptor>`

func Test_IDPSSODescriptor_Attributes(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	ed := &metadata.EntityDescriptorIDPSSO{}

	err := xml.Unmarshal([]byte(exampleIDPSSODescriptorAttributes), ed)
	r.NoError(err)

	r.Len(ed.IDPSSODescriptor, 1)

	attr := ed.IDPSSODescriptor[0].Attribute

	r.Len(attr, 2)

	r.Equal(attr[0].NameFormat, string(core.NameFormatURI))
	r.Equal(attr[0].Name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.6")

	r.Equal(attr[1].NameFormat, string(core.NameFormatURI))
	r.Equal(attr[1].Name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.1")

	r.Len(attr[1].AttributeValue, 5)
	r.Equal(attr[1].AttributeValue[0].Value, "member")
	r.Equal(attr[1].AttributeValue[1].Value, "student")
	r.Equal(attr[1].AttributeValue[2].Value, "faculty")
	r.Equal(attr[1].AttributeValue[3].Value, "employee")
	r.Equal(attr[1].AttributeValue[4].Value, "staff")
}
