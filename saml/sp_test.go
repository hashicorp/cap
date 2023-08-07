package saml_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
	testprovider "github.com/hashicorp/cap/saml/test"
)

func Test_NewServiceProvider(t *testing.T) {
	r := require.New(t)
	exampleURL, err := url.Parse("http://test.me")
	r.NoError(err)

	cases := []struct {
		name string
		cfg  *saml.Config
		err  string
	}{
		{
			name: "When a valid config is provided",
			cfg: &saml.Config{
				AssertionConsumerServiceURL: exampleURL,
				Issuer:                      exampleURL,
				MetadataURL:                 exampleURL,
				EntityID:                    exampleURL,
			},
			err: "",
		},
		{
			name: "When an invalid config is provided",
			cfg:  &saml.Config{},
			err:  "saml.NewServiceProvider: insufficient provider config:",
		},
		{
			name: "When no config is provided",
			cfg:  nil,
			err:  "saml.NewServiceProvider: no provider config provided",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(_ *testing.T) {
			got, err := saml.NewServiceProvider(c.cfg)

			if c.err != "" {
				r.Error(err)
				r.ErrorContains(err, c.err)
			} else {
				r.NoError(err)
				r.NotNil(got)
				r.NotNil(got.Config())
			}
		})
	}
}

func Test_CreateAuthnRequest(t *testing.T) {
	r := require.New(t)

	tp := testprovider.StartTestProvider(t)
	defer tp.Close()

	entityID, err := url.Parse("http://test.me/entity")
	r.NoError(err)

	acs, err := url.Parse("http://test.me/saml/acs")
	r.NoError(err)

	issuer, err := url.Parse("http://test.idp")
	r.NoError(err)

	metaURL := fmt.Sprintf("%s/saml/metadata", tp.ServerURL())
	metadata, err := url.Parse(metaURL)
	r.NoError(err)

	cfg, err := saml.NewConfig(
		entityID,
		acs,
		issuer,
		metadata,
	)

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	cases := []struct {
		name    string
		id      string
		binding core.ServiceBinding
		err     string
	}{
		{
			name:    "With service binding post",
			id:      "abc123",
			binding: core.ServiceBindingHTTPPost,
			err:     "",
		},
		{
			name:    "With service binding redirect",
			id:      "abc123",
			binding: core.ServiceBindingHTTPRedirect,
			err:     "",
		},
		{
			name:    "When there is no ID provided",
			id:      "",
			binding: core.ServiceBindingHTTPRedirect,
			err:     "saml.ServiceProvider.CreateAuthnRequest: no ID provided: invalid parameter",
		},
		{
			name:    "When there is no binding provided",
			id:      "abc123",
			binding: "",
			err:     "saml.ServiceProvider.CreateAuthnRequest: no binding provided: invalid parameter",
		},
		{
			name:    "When there there is no destination for the given binding",
			id:      "abc123",
			binding: core.ServiceBinding("non-existing"),
			err:     "saml.ServiceProvider.CreateAuthnRequest: failed to get destination for given service binding (non-existing):",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(_ *testing.T) {
			got, err := provider.CreateAuthnRequest(c.id, c.binding)
			if c.err != "" {
				r.Error(err)
				r.ErrorContains(err, c.err)
			} else {
				r.NoError(err)

				switch c.binding {
				case core.ServiceBindingHTTPPost:
					loc := fmt.Sprintf("%s/saml/login/post", tp.ServerURL())
					r.Equal(loc, got.Destination)
				case core.ServiceBindingHTTPRedirect:
					loc := fmt.Sprintf("%s/saml/login/redirect", tp.ServerURL())
					r.Equal(loc, got.Destination)
				}

				r.Equal(c.id, got.ID)
				r.Equal("2.0", got.Version)
				r.Equal(core.ServiceBindingHTTPPost, got.ProtocolBinding)
				r.Equal("http://test.me/saml/acs", got.AssertionConsumerServiceURL)
				r.Equal("http://test.me/entity", got.Issuer.Value)
				r.Equal(core.NameIDFormatEmail, got.NameIDPolicy.Format)
				r.False(got.NameIDPolicy.AllowCreate)
				r.False(got.ForceAuthn)
			}
		})
	}
}

func Test_ServiceProvider_FetchMetadata_ErrorCases(t *testing.T) {
	r := require.New(t)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<invalidXML//>"))
	}))
	defer s.Close()

	fakeURL, err := url.Parse("http://cap.saml.fake")
	r.NoError(err)

	meta := fmt.Sprintf("%s/saml/metadata", s.URL)
	metaURL, err := url.Parse(meta)
	r.NoError(err)

	cfg, err := saml.NewConfig(
		fakeURL,
		fakeURL,
		fakeURL,
		fakeURL,
	)
	r.NoError(err)

	cases := []struct {
		name     string
		metadata *url.URL
		wantErr  string
	}{
		{
			name:     "When the metadata can't be fetched",
			metadata: fakeURL,
			wantErr:  "saml.ServiceProvider.FetchMetdata: failed to fetch metadata:",
		},
		{
			name:     "When the metadata XML can't be parsed",
			metadata: metaURL,
			wantErr:  "saml.ServiceProvider.FetchMetdata: failed to parse metadata XML:",
		},
	}

	for _, c := range cases {
		cfg.MetadataURL = c.metadata

		provider, err := saml.NewServiceProvider(cfg)
		r.NoError(err)

		t.Run(c.name, func(_ *testing.T) {
			got, err := provider.FetchMetadata()
			r.Nil(got)
			r.Error(err)
			r.ErrorContains(err, c.wantErr)
		})
	}
}

func Test_ServiceProvider_CreateMetadata(t *testing.T) {
	r := require.New(t)

	entityID, err := url.Parse("http://test.me/entity")
	r.NoError(err)

	acs, err := url.Parse("http://test.me/saml/acs")
	r.NoError(err)

	issuer, err := url.Parse("http://test.idp")
	r.NoError(err)

	meta, err := url.Parse("http://test.idp/metadata")
	r.NoError(err)

	now := time.Now()
	validUntil := func() time.Time {
		return now
	}

	cfg, err := saml.NewConfig(
		entityID,
		acs,
		issuer,
		meta,
	)

	cfg.ValidUntil = validUntil

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	cases := []struct {
		name string
	}{
		{
			name: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(_ *testing.T) {
			got := provider.CreateMetadata()

			r.Equal(now, got.ValidUntil)
			r.Equal("http://test.me/entity", got.EntityID)

			r.Len(got.SPSSODescriptor, 1)
			r.True(got.SPSSODescriptor[0].WantAssertionsSigned)
			r.False(got.SPSSODescriptor[0].AuthnRequestsSigned)
			r.Equal(
				metadata.ProtocolSupportEnumerationProtocol,
				got.SPSSODescriptor[0].ProtocolSupportEnumeration,
			)
			r.Equal(
				core.ServiceBindingHTTPPost,
				got.SPSSODescriptor[0].AssertionConsumerService[0].Binding,
			)
			r.Equal(1, got.SPSSODescriptor[0].AssertionConsumerService[0].Index)
			r.Equal(
				"http://test.me/saml/acs",
				got.SPSSODescriptor[0].AssertionConsumerService[0].Location,
			)
			r.Contains(got.SPSSODescriptor[0].NameIDFormat, core.NameIDFormatEmail)
			r.Contains(got.SPSSODescriptor[0].NameIDFormat, core.NameIDFormatTransient)
		})
	}
}
