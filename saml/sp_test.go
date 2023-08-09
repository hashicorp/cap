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
		})
	}
}

func Test_CreateMetadata_Options(t *testing.T) {
	r := require.New(t)

	fakeURL, err := url.Parse("http://fake.test.url")
	r.NoError(err)

	cfg, err := saml.NewConfig(
		fakeURL,
		fakeURL,
		fakeURL,
		fakeURL,
	)

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	t.Run("When option InsecureWantAssertionsUnsigned is set", func(_ *testing.T) {
		got := provider.CreateMetadata(
			saml.InsecureWantAssertionsUnsigned(),
		)

		r.False(got.SPSSODescriptor[0].WantAssertionsSigned)
	})

	t.Run("When option WithAdditionalNameIDFormat is set", func(_ *testing.T) {
		got := provider.CreateMetadata(
			saml.WithAdditionalNameIDFormat(core.NameIDFormatTransient),
		)

		r.Len(got.SPSSODescriptor[0].NameIDFormat, 2)
		r.Contains(got.SPSSODescriptor[0].NameIDFormat, core.NameIDFormatTransient)
	})

	t.Run("When option WithNameIDFormats is set", func(_ *testing.T) {
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

	t.Run("When option WithACSServiceBinding is set", func(_ *testing.T) {
		got := provider.CreateMetadata(
			saml.WithACSServiceBinding(core.ServiceBindingHTTPRedirect),
		)

		r.Len(got.SPSSODescriptor[0].AssertionConsumerService, 1)
		r.Equal(
			got.SPSSODescriptor[0].AssertionConsumerService[0].Binding,
			core.ServiceBindingHTTPRedirect,
		)
	})

	t.Run("When option WithAdditionalACSEndpoint is set", func(_ *testing.T) {
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
					Location: fakeURL.String(),
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
