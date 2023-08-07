package testprovider

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

const meta = `
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://test.idp">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>cert</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://test.idp/saml/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test.idp/saml/redirect"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`

type TestProvider struct {
	t      *testing.T
	server *httptest.Server

	metadata *metadata.EntityDescriptorIDPSSO
}

func StartTestProvider(t *testing.T) *TestProvider {
	t.Helper()
	r := require.New(t)

	var m metadata.EntityDescriptorIDPSSO
	err := xml.Unmarshal([]byte(meta), &m)
	r.NoError(err)

	provider := &TestProvider{
		t:        t,
		metadata: &m,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/saml/metadata", provider.MetadataHandler)
	mux.HandleFunc("/saml/login/post", provider.LoginHandlerPost)
	mux.HandleFunc("/saml/login/redirect", provider.LoginHandlerRedirect)

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

func (p *TestProvider) Close() {
	p.server.Close()
}

func (p *TestProvider) ServerURL() string {
	return p.server.URL
}

func (p *TestProvider) MetadataHandler(w http.ResponseWriter, _ *http.Request) {
	p.t.Helper()
	r := require.New(p.t)

	err := xml.NewEncoder(w).Encode(p.metadata)
	r.NoError(err)
}

func (p *TestProvider) LoginHandlerPost(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (p *TestProvider) LoginHandlerRedirect(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
