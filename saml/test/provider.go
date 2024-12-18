// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testprovider

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

// ID must start with a letter or underscore.
var idRegexp = regexp.MustCompile(`\A[a-zA-Z_]`)

const meta = `
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://test.idp">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://test.idp/saml/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test.idp/saml/redirect"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`

// From https://www.samltool.com/generic_sso_res.php
const ResponseSigned = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="test-request-id">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfxb5993e9c-fa1b-d9c7-6b1a-041362d1cefb" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxb5993e9c-fa1b-d9c7-6b1a-041362d1cefb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>CtIHbEceX42xKr7zJ/642uXWROg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ALoS5nPK3X14WITy+5W/GYbdfpBBfqYugw3R69+QQa0pu7hy0VG2nr5LzEe4n1YbLd0rA2q5N6jtCuicv9Mfvk9SatkNhuP1TDnIeX4muOx/tu7hkCyaR9IeLfIVa9kohi1uGLqffGTBNUlIO0PpCPxwlmKCiio4zOUa/Dln8vs=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

// SAMLResponsePostData represents the SAML response data that is expected
// in the form data of a POST request.
type SAMLResponsePostData struct {
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state"`
	Destination  string `json:"destination"`
}

// PostRequest creates an http POST request with the SAML response and relay state
// included as form data.
func (s *SAMLResponsePostData) PostRequest(t *testing.T) *http.Request {
	t.Helper()
	r := require.New(t)

	form := url.Values{}
	form.Add("SAMLResponse", s.SAMLResponse)
	form.Add("RelayState", s.RelayState)

	req, err := http.NewRequest(http.MethodPost, s.Destination, strings.NewReader(form.Encode()))
	r.NoError(err)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return req
}

// TestProvider is an identity provider that can be used for testing
// SAML federeation and authentication flows.
type TestProvider struct {
	t        *testing.T
	server   *httptest.Server
	keystore dsig.X509KeyStore

	metadata *metadata.EntityDescriptorIDPSSO
	recorder *httptest.ResponseRecorder
	result   *http.Response

	expectedRelayState      string
	expectedVersion         string
	expectedIssuer          string
	expectedProtocolBinding string
	expectedACSURL          string
	expectedRequestID       string
	expectInvalidRequestID  bool
	expectedIssueInstant    time.Time

	expectedB64EncSAMLRequest string
}

func (p *TestProvider) defaults() {
	p.expectedVersion = "2.0"
	p.expectedProtocolBinding = string(core.ServiceBindingHTTPPost)
}

// SetExpectedRelayState sets the expected RelayState value.
func (p *TestProvider) SetExpectedRelayState(rs string) {
	p.expectedRelayState = rs
}

// SetExpectedIssuer sets the in the SAML request expected issuer value.
func (p *TestProvider) SetExpectedIssuer(sr string) {
	p.expectedIssuer = sr
}

// SetExpectedProtocolBinding sets the in the SAML request expected protocol binding.
// Defaults to the HTTP-POST binding.
func (p *TestProvider) SetExpectedProtocolBinding(pb string) {
	p.expectedProtocolBinding = pb
}

// SetExpectedACSURL sets the in the SAML request expected assertion consumer service URL.
func (p *TestProvider) SetExpectedACSURL(acs string) {
	p.expectedACSURL = acs
}

// SetExpectedRequestID sets the in the SAML request expected request ID.
func (p *TestProvider) SetExpectedRequestID(id string) {
	p.expectedRequestID = id
}

// ExpectInvalidRequestID expects that the ID isn't XSD:ID conform.
func (p *TestProvider) ExpectedInvalidRequestID() {
	p.expectInvalidRequestID = true
}

// SetExpectedACSURL sets the in the SAML request expected issue instant value.
func (p *TestProvider) SetExpectedIssueInstant(ii time.Time) {
	p.expectedIssueInstant = ii
}

// SetExpectedSAMLRequest sets the expected SAML request.
func (p *TestProvider) SetExpectedBase64EncodedSAMLRequest(sr string) {
	p.expectedB64EncSAMLRequest = sr
}

// StartTestProvider starts a new identity provider for testing.
// The metadata XML is served at the "/saml/metadata" path.
// The server URL can be obtained by calling the ServerURL() method.
//
// The metadata XML contains the HTTP-Post and Redirect sign-on endpoints.
// The sign-on endpoints will validate the incoming requests on their correctness.
// The SAMLResponse, RelayState, and Destination URL will be returned in a JSON file,
// that can be unmarshalled into testprovider.SAMLResponsePostData.
func StartTestProvider(t *testing.T) *TestProvider {
	t.Helper()
	r := require.New(t)

	var m metadata.EntityDescriptorIDPSSO
	err := xml.Unmarshal([]byte(meta), &m)
	r.NoError(err)

	keystore := dsig.RandomKeyStoreForTest()
	_, cert, err := keystore.GetKeyPair()
	r.NoError(err)

	b64Cert := base64.StdEncoding.EncodeToString(cert)

	m.IDPSSODescriptor[0].RoleDescriptor.KeyDescriptor[0].KeyInfo.X509Data.X509Certificates[0].Data = b64Cert

	provider := &TestProvider{
		t:        t,
		metadata: &m,
		keystore: keystore,
	}

	provider.defaults()

	mux := http.NewServeMux()
	mux.HandleFunc("/saml/metadata", provider.metadataHandler)
	mux.HandleFunc("/saml/login/post", provider.loginHandlerPost)
	mux.HandleFunc("/saml/login/redirect", provider.loginHandlerRedirect)

	server := httptest.NewUnstartedServer(mux)
	provider.server = server

	server.Start()

	overrideSSOLocations(server.URL, &m)

	return provider
}

func overrideSSOLocations(serverURL string, metadata *metadata.EntityDescriptorIDPSSO) {
	ssoDescriptor := metadata.IDPSSODescriptor[0]
	for i, sso := range ssoDescriptor.SingleSignOnService {
		if sso.Binding == core.ServiceBindingHTTPPost {
			sso.Location = fmt.Sprintf("%s/saml/login/post", serverURL)
			ssoDescriptor.SingleSignOnService[i] = sso
		}

		if sso.Binding == core.ServiceBindingHTTPRedirect {
			sso.Location = fmt.Sprintf("%s/saml/login/redirect", serverURL)
			ssoDescriptor.SingleSignOnService[i] = sso
		}
	}
}

// Close shut downs the server and waits for all requests to complete.
func (p *TestProvider) Close() {
	p.server.Close()
}

// ServerURL returns the test server URL.
func (p *TestProvider) ServerURL() string {
	return p.server.URL
}

func (p *TestProvider) metadataHandler(w http.ResponseWriter, _ *http.Request) {
	p.t.Helper()
	r := require.New(p.t)

	err := xml.NewEncoder(w).Encode(p.metadata)
	r.NoError(err)
}

func (p *TestProvider) loginHandlerPost(w http.ResponseWriter, req *http.Request) {
	p.t.Helper()
	r := require.New(p.t)

	err := req.ParseForm()
	r.NoError(err)

	rawReq := req.FormValue("SAMLRequest")
	r.NotEmpty(rawReq)

	// do not check the base64 encoded saml request if not explicitly set.
	if p.expectedB64EncSAMLRequest != "" {
		r.Equal(p.expectedB64EncSAMLRequest, rawReq)
	}

	relayState := req.FormValue("RelayState")

	r.Equal(p.expectedRelayState, relayState, "relay state doesn't match")

	samlReq := p.parseRequestPost(rawReq)

	p.validateRequest(samlReq)

	samlResponseData := &SAMLResponsePostData{
		SAMLResponse: ResponseSigned,
		RelayState:   relayState,
		Destination:  samlReq.AssertionConsumerServiceURL,
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(samlResponseData)
	r.NoError(err, "failed to encode SAML response data")
}

func (p *TestProvider) loginHandlerRedirect(w http.ResponseWriter, req *http.Request) {
	p.t.Helper()
	r := require.New(p.t)

	rawReq := req.URL.Query().Get("SAMLRequest")
	r.NotEmpty(rawReq)

	// do not check the base64 encoded saml request if not explicitly set.
	if p.expectedB64EncSAMLRequest != "" {
		r.Equal(p.expectedB64EncSAMLRequest, rawReq)
	}

	relayState := req.URL.Query().Get("RelayState")

	r.Equal(p.expectedRelayState, relayState, "relay state doesn't match")

	samlReq := p.parseRequestRedirect(rawReq)
	r.NotNil(samlReq, "the saml request must not be nil")

	p.validateRequest(samlReq)

	samlResponseData := &SAMLResponsePostData{
		SAMLResponse: ResponseSigned,
		RelayState:   relayState,
		Destination:  samlReq.AssertionConsumerServiceURL,
	}

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(samlResponseData)
	r.NoError(err, "failed to encode SAML response data")
}

func (p *TestProvider) validateRequest(samlReq *core.AuthnRequest) {
	p.t.Helper()
	r := require.New(p.t)

	r.Equal(
		p.expectedVersion,
		samlReq.Version,
		fmt.Sprintf("the SAML version doesn't match. Got: %s", samlReq.Version),
	)

	expectedDestination := fmt.Sprintf("%s/saml/login/redirect", p.server.URL)
	r.Equal(
		expectedDestination,
		samlReq.Destination,
		"the destination must match the HTTP redirect location from the IDP metadata",
	)

	if p.expectInvalidRequestID {
		r.False(
			idRegexp.MatchString(samlReq.ID),
			"expected an invalid SAML request ID but it's valid",
		)
	} else {
		r.True(
			idRegexp.MatchString(samlReq.ID),
			fmt.Sprintf(
				"first letter of the SAML request ID must be a letter or underscore. Got: %s",
				samlReq.ID,
			),
		)
	}

	r.Equal(
		p.expectedIssuer,
		samlReq.Issuer.Value,
		"the issuer value doesn't match the expected issuer",
	)

	r.Equal(
		p.expectedProtocolBinding,
		string(samlReq.ProtocolBinding),
		"SAML protocol binding doesn't match",
	)

	r.Equal(
		p.expectedACSURL,
		samlReq.AssertionConsumerServiceURL,
		"ACS URL doesn't match",
	)

	// TODO: Add an option to set an issue instant
	// r.Equal(
	// 	p.expectedIssueInstant, samlReq.IssueInstant, "issue instant doesn't match",
	// )

	if p.expectedRequestID != "" {
		r.Equal(
			p.expectedRequestID,
			samlReq.ID,
			"expected request ID doesn't match the ID in the SAML request",
		)
	}
}

func (p *TestProvider) parseRequestRedirect(request string) *core.AuthnRequest {
	p.t.Helper()
	r := require.New(p.t)

	deflated, err := base64.StdEncoding.DecodeString(request)
	r.NoError(err, "couldn't base64 decode SAML request")

	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	r.NoError(err, "couldn't uncompress (deflated) SAML request")

	req := core.AuthnRequest{}
	err = xml.Unmarshal(raw, &req)
	r.NoError(err, "couldn't unmarshal SAML request")

	return &req
}

func (p *TestProvider) parseRequestPost(request string) *core.AuthnRequest {
	p.t.Helper()
	r := require.New(p.t)

	raw, err := base64.StdEncoding.DecodeString(request)
	r.NoError(err, "couldn't base64 decode SAML request")

	req := core.AuthnRequest{}
	err = xml.Unmarshal(raw, &req)
	r.NoError(err, "couldn't unmarshal SAML request")

	return &req
}

type responseOptions struct {
	signResponseElem  bool
	signAssertionElem bool
	expired           bool
}

type ResponseOption func(*responseOptions)

func getResponseOptions(opts ...ResponseOption) *responseOptions {
	defaults := defaultResponseOptions()
	for _, o := range opts {
		o(defaults)
	}

	return defaults
}

func defaultResponseOptions() *responseOptions {
	return &responseOptions{}
}

func WithResponseAndAssertionSigned() ResponseOption {
	return func(o *responseOptions) {
		o.signResponseElem = true
		o.signAssertionElem = true
	}
}

func WithJustAssertionSigned() ResponseOption {
	return func(o *responseOptions) {
		o.signAssertionElem = true
	}
}

func WithJustResponseSigned() ResponseOption {
	return func(o *responseOptions) {
		o.signResponseElem = true
	}
}

func WithResponseExpired() ResponseOption {
	return func(o *responseOptions) {
		o.expired = true
	}
}

func (p *TestProvider) SamlResponse(t *testing.T, opts ...ResponseOption) string {
	r := require.New(t)

	opt := getResponseOptions(opts...)

	notOnOrAfter := "2200-01-18T06:21:48Z"

	if opt.expired {
		notOnOrAfter = "2001-01-18T06:21:48Z"
	}

	response := &core.Response{
		Response: types.Response{
			Destination:  "http://hashicorp-cap.test/saml/acs",
			ID:           "test-resp-id",
			InResponseTo: "test-request-id",
			IssueInstant: time.Now(),
			Version:      "2.0",
			Issuer: &types.Issuer{
				Value: "http://test.idp",
			},
			Status: &types.Status{
				StatusCode: &types.StatusCode{
					Value: string(core.StatusCodeSuccess),
				},
			},
			Assertions: []types.Assertion{
				{
					ID: "assertion-id",
					Issuer: &types.Issuer{
						Value: "http://test.idp",
					},
					Subject: &types.Subject{
						NameID: &types.NameID{
							Value: "name-id",
						},
						SubjectConfirmation: &types.SubjectConfirmation{
							Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
							SubjectConfirmationData: &types.SubjectConfirmationData{
								InResponseTo: "test-request-id",
								Recipient:    "http://hashicorp-cap.test/saml/acs",
								NotOnOrAfter: notOnOrAfter,
							},
						},
					},
					Conditions: &types.Conditions{
						NotBefore:    "2001-01-18T06:21:48Z",
						NotOnOrAfter: notOnOrAfter,
						AudienceRestrictions: []types.AudienceRestriction{
							{
								Audiences: []types.Audience{
									{Value: "http://hashicorp-cap.test"},
								},
							},
						},
					},
					AttributeStatement: &types.AttributeStatement{
						Attributes: []types.Attribute{
							{
								Name:       "mail",
								NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								Values: []types.AttributeValue{
									{
										Type:  "xs:string",
										Value: "user@hashicorp-cap.test",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	resp, err := xml.Marshal(response)
	r.NoError(err)

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(resp)
	r.NoError(err)

	if opt.signResponseElem || opt.signAssertionElem {
		signCtx := dsig.NewDefaultSigningContext(p.keystore)

		// sign child object assertions
		// note we will sign the `assertion` first and then only the parent `response`, because the `response`
		// signature is based on the entire contents of `response` (including `assertion` signature)
		if opt.signAssertionElem {
			responseEl := doc.SelectElement("Response")
			for _, assert := range responseEl.FindElements("Assertion") {
				signedAssert, err := signCtx.SignEnveloped(assert)
				r.NoError(err)

				// replace signed assert object
				responseEl.RemoveChildAt(assert.Index())
				responseEl.AddChild(signedAssert)
			}
		}

		// sign root object response
		if opt.signResponseElem {
			signed, err := signCtx.SignEnveloped(doc.Root())
			r.NoError(err)
			doc.SetRoot(signed)
		}
	}

	result, err := doc.WriteToString()
	r.NoError(err)

	return result
}
