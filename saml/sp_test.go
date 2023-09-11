package saml_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
	"github.com/hashicorp/cap/saml/models/metadata"
)

func Test_NewServiceProvider(t *testing.T) {
	r := require.New(t)
	exampleURL := "http://test.me"

	validConfig, err := saml.NewConfig(
		exampleURL,
		exampleURL,
		exampleURL,
	)
	r.NoError(err)

	cases := []struct {
		name string
		cfg  *saml.Config
		err  string
	}{
		{
			name: "When a valid config is provided",
			cfg:  validConfig,
			err:  "",
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
		t.Run(c.name, func(t *testing.T) {
			r := require.New(t)
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

func Test_ServiceProvider_FetchMetadata_ErrorCases(t *testing.T) {
	r := require.New(t)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<invalidXML//>"))
	}))
	defer s.Close()

	fakeURL := "http://cap.saml.fake"
	metaURL := fmt.Sprintf("%s/saml/metadata", s.URL)

	cfg, err := saml.NewConfig(
		fakeURL,
		fakeURL,
		fakeURL,
	)
	r.NoError(err)

	cases := []struct {
		name     string
		metadata string
		wantErr  string
	}{
		{
			name:     "When the metadata can't be fetched",
			metadata: fakeURL,
			wantErr:  "saml.ServiceProvider.FetchIDPMetadata: failed to fetch identity provider metadata:",
		},
		{
			name:     "When the metadata XML can't be parsed",
			metadata: metaURL,
			wantErr:  "saml.ServiceProvider.FetchIDPMetadata: failed to parse identity provider XML metadata:",
		},
	}

	for _, c := range cases {
		cfg.MetadataURL = c.metadata

		provider, err := saml.NewServiceProvider(cfg)
		r.NoError(err)

		t.Run(c.name, func(t *testing.T) {
			r := require.New(t)
			got, err := provider.IDPMetadata()
			r.Nil(got)
			r.Error(err)
			r.ErrorContains(err, c.wantErr)
		})
	}
}

func Test_ServiceProvider_FetchMetadata_Cache(t *testing.T) {
	type testServer struct {
		fail          bool
		failOnRefresh bool
	}

	newTestServer := func(t *testing.T, failOnRefresh bool) string {
		t.Helper()

		ts := &testServer{false, failOnRefresh}

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if !ts.fail {
				w.Write([]byte(exampleIDPSSODescriptorX))
			}
			ts.fail = ts.fail || ts.failOnRefresh
		}))
		t.Cleanup(s.Close)

		return s.URL
	}

	cases := []struct {
		name                 string
		newTime              string
		shouldBeCached       bool
		opts                 []saml.Option
		failOnRefresh        bool
		expectErrorOnRefresh bool
	}{
		{
			name:           "is cached",
			shouldBeCached: true,
		},
		{
			name:           "cache is disabled",
			opts:           []saml.Option{saml.WithCache(false)},
			shouldBeCached: false,
		},
		{
			name:           "stale cached document should not be used",
			newTime:        "2017-07-26",
			shouldBeCached: false,
		},
		{
			name:                 "is not cached once validUntil is reached",
			newTime:              "2018-07-25",
			expectErrorOnRefresh: true,
		},
		{
			name:                 "a stale document should not be used if refreshing fails",
			newTime:              "2017-07-26",
			failOnRefresh:        true,
			expectErrorOnRefresh: true,
		},
		{
			name:           "use stale document",
			opts:           []saml.Option{saml.WithStale(true)},
			newTime:        "2017-07-26",
			failOnRefresh:  true,
			shouldBeCached: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			url := newTestServer(t, tt.failOnRefresh)
			metaURL := fmt.Sprintf("%s/saml/metadata", url)
			cfg, err := saml.NewConfig(
				metaURL,
				metaURL,
				metaURL,
			)
			r.NoError(err)

			provider, err := saml.NewServiceProvider(cfg)
			r.NoError(err)

			newTime, err := time.Parse("2006-01-02", "2017-07-25")
			r.NoError(err)

			opts := append([]saml.Option{saml.WithClock(clockwork.NewFakeClockAt(newTime))}, tt.opts...)

			got1, err := provider.IDPMetadata(opts...)
			r.NoError(err)
			r.NotNil(got1)

			if tt.newTime != "" {
				newTime, err = time.Parse("2006-01-02", tt.newTime)
				r.NoError(err)
				opts = append(opts, saml.WithClock(clockwork.NewFakeClockAt(newTime)))
			}

			got2, err := provider.IDPMetadata(opts...)
			if tt.expectErrorOnRefresh {
				r.Error(err)
				return
			} else {
				r.NoError(err)
			}
			r.NotNil(got2)

			if tt.shouldBeCached {
				r.True(got1 == got2)
			} else {
				r.False(got1 == got2)
			}
		})
	}
}

func Test_ServiceProvider_CreateMetadata(t *testing.T) {
	r := require.New(t)

	entityID := "http://test.me/entity"
	acs := "http://test.me/saml/acs"
	meta := "http://test.me/sso/metadata"

	now := time.Now()
	validUntil := func() time.Time {
		return now
	}

	cfg, err := saml.NewConfig(
		entityID,
		acs,
		meta,
	)
	r.NoError(err)

	cfg.ValidUntil = validUntil

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	cases := []struct {
		name          string
		nameIDFormats []core.NameIDFormat
	}{
		{
			name: "",
		},
		{
			name:          "email",
			nameIDFormats: []core.NameIDFormat{core.NameIDFormatEmail},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := require.New(t)
			opts := []saml.Option{}
			if c.nameIDFormats != nil {
				opts = append(opts, saml.WithNameIDFormats(c.nameIDFormats))
			}
			got := provider.CreateMetadata(opts...)

			r.Equal(&now, got.ValidUntil)
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
			r.Equal(got.SPSSODescriptor[0].NameIDFormat, c.nameIDFormats)
		})
	}
}

func Test_CreateMetadata_Options(t *testing.T) {
	r := require.New(t)

	fakeURL := "http://fake.test.url"

	cfg, err := saml.NewConfig(
		fakeURL,
		fakeURL,
		fakeURL,
	)

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	t.Run("When option InsecureWantAssertionsUnsigned is set", func(t *testing.T) {
		r := require.New(t)
		got := provider.CreateMetadata(
			saml.InsecureWantAssertionsUnsigned(),
		)

		r.False(got.SPSSODescriptor[0].WantAssertionsSigned)
	})

	t.Run("When option WithAdditionalNameIDFormat is set", func(t *testing.T) {
		r := require.New(t)
		got := provider.CreateMetadata(
			saml.WithAdditionalNameIDFormat(core.NameIDFormatTransient),
		)

		r.Equal(got.SPSSODescriptor[0].NameIDFormat, []core.NameIDFormat{core.NameIDFormatTransient})
	})

	t.Run("When option WithNameIDFormats is set", func(t *testing.T) {
		r := require.New(t)
		got := provider.CreateMetadata(
			saml.WithNameIDFormats([]core.NameIDFormat{
				core.NameIDFormatEntity,
				core.NameIDFormatUnspecified,
			}),
		)

		r.Len(got.SPSSODescriptor[0].NameIDFormat, 2)
		r.Equal(got.SPSSODescriptor[0].NameIDFormat, []core.NameIDFormat{
			core.NameIDFormatEntity,
			core.NameIDFormatUnspecified,
		})
	})

	t.Run("When option WithACSServiceBinding is set", func(t *testing.T) {
		r := require.New(t)
		got := provider.CreateMetadata(
			saml.WithACSServiceBinding(core.ServiceBindingHTTPRedirect),
		)

		r.Len(got.SPSSODescriptor[0].AssertionConsumerService, 1)
		r.Equal(
			got.SPSSODescriptor[0].AssertionConsumerService[0].Binding,
			core.ServiceBindingHTTPRedirect,
		)
	})

	t.Run("When option WithAdditionalACSEndpoint is set", func(t *testing.T) {
		r := require.New(t)
		redirectEndpoint, err := url.Parse("http://cap.saml.test/acs/redirect")
		r.NoError(err)

		got := provider.CreateMetadata(
			saml.WithAdditionalACSEndpoint(
				core.ServiceBindingHTTPRedirect,
				redirectEndpoint,
			),
		)

		r.Len(got.SPSSODescriptor[0].AssertionConsumerService, 2)
		r.Equal(
			got.SPSSODescriptor[0].AssertionConsumerService[0],
			metadata.IndexedEndpoint{
				Endpoint: metadata.Endpoint{
					Binding:  core.ServiceBindingHTTPPost,
					Location: fakeURL,
				},
				Index: 1,
			},
		)

		r.Equal(
			got.SPSSODescriptor[0].AssertionConsumerService[1],
			metadata.IndexedEndpoint{
				Endpoint: metadata.Endpoint{
					Binding:  core.ServiceBindingHTTPRedirect,
					Location: redirectEndpoint.String(),
				},
				Index: 2,
			},
		)
	})
}

var exampleIDPSSODescriptorX = `<md:EntityDescriptor entityID="https://sso.example.info/entity" validUntil="2017-08-30T19:10:29Z" cacheDuration="PT15M"
xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<!-- insert ds:Signature element (omitted) -->
<md:Extensions>
  <mdrpi:RegistrationInfo registrationAuthority="https://registrar.example.net"/>
  <mdrpi:PublicationInfo creationInstant="2017-08-16T19:10:29Z" publisher="https://registrar.example.net"/>
  <mdattr:EntityAttributes>
	<saml:Attribute Name="http://registrar.example.net/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
	  <saml:AttributeValue>https://registrar.example.net/category/self-certified</saml:AttributeValue>
	</saml:Attribute>
  </mdattr:EntityAttributes>
</md:Extensions>
<!-- insert one or more concrete instances of the md:RoleDescriptor abstract type (see below) -->
<md:Organization>
  <md:OrganizationName xml:lang="en">...</md:OrganizationName>
  <md:OrganizationDisplayName xml:lang="en">...</md:OrganizationDisplayName>
  <md:OrganizationURL xml:lang="en">https://www.example.info/</md:OrganizationURL>
</md:Organization>
<md:ContactPerson contactType="technical">
  <md:SurName>SAML Technical Support</md:SurName>
  <md:EmailAddress>mailto:technical-support@example.info</md:EmailAddress>
</md:ContactPerson>
</md:EntityDescriptor>
`
