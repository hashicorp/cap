package saml_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
	testprovider "github.com/hashicorp/cap/saml/test"
)

func Test_CreateAuthnRequest(t *testing.T) {
	r := require.New(t)

	tp := testprovider.StartTestProvider(t)
	defer tp.Close()

	cfg, err := saml.NewConfig(
		"http://test.me/entity",
		"http://test.me/saml/acs",
		fmt.Sprintf("%s/saml/metadata", tp.ServerURL()),
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
				r.Nil(got.NameIDPolicy)
				r.Nil(got.RequestedAuthContext)
				r.False(got.ForceAuthn)
			}
		})
	}
}

func Test_CreateAuthnRequest_Options(t *testing.T) {
	r := require.New(t)

	tp := testprovider.StartTestProvider(t)
	defer tp.Close()

	cfg, err := saml.NewConfig(
		"http://test.me/entity",
		"http://test.me/saml/acs",
		fmt.Sprintf("%s/saml/metadata", tp.ServerURL()),
	)

	provider, err := saml.NewServiceProvider(cfg)
	r.NoError(err)

	t.Run("When option AllowCreate is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.AllowCreate(),
		)

		r.NoError(err)

		r.NotNil(got.NameIDPolicy)
		r.True(got.NameIDPolicy.AllowCreate)
	})

	t.Run("When option WithNameIDFormat is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.WithNameIDFormat(core.NameIDFormatEmail),
		)

		r.NoError(err)

		r.NotNil(got.NameIDPolicy)
		r.True(got.NameIDPolicy.AllowCreate)
		r.Equal(core.NameIDFormatEmail, got.NameIDPolicy.Format)
	})

	t.Run("When option ForceAuthn is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.ForceAuthn(),
		)

		r.NoError(err)
		r.True(got.ForceAuthn)
	})

	t.Run("When option WithProtocolBinding is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.WithProtocolBinding(core.ServiceBindingHTTPRedirect),
		)

		r.NoError(err)
		r.Equal(core.ServiceBindingHTTPRedirect, got.ProtocolBinding)
	})

	t.Run("When option WithAuthnContextRefs is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.WithAuthContextClassRefs([]string{
				"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			}),
		)

		r.NoError(err)
		r.Contains(
			got.RequestedAuthContext.AuthnConextClassRef,
			"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		)
		r.Equal(core.ComparisonExact, got.RequestedAuthContext.Comparison)
	})

	t.Run("When more than one option is set", func(_ *testing.T) {
		got, err := provider.CreateAuthnRequest(
			"abc123",
			core.ServiceBindingHTTPPost,
			saml.ForceAuthn(),
			saml.WithProtocolBinding(core.ServiceBindingHTTPRedirect),
		)

		r.NoError(err)
		r.True(got.ForceAuthn)
		r.Equal(core.ServiceBindingHTTPRedirect, got.ProtocolBinding)
	})

	r.NoError(err)
}
