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
				*redirectEndpoint,
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
