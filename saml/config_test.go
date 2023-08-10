package saml_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
)

func Test_NewConfig(t *testing.T) {
	r := require.New(t)

	entityID, err := url.Parse("http://test.me/entity")
	r.NoError(err)

	acs, err := url.Parse("http://test.me/sso/acs")
	r.NoError(err)

	issuer, err := url.Parse("http://test.me")
	r.NoError(err)

	metadata, err := url.Parse("http://test.me/sso/metadata")
	r.NoError(err)

	cases := []struct {
		name        string
		entityID    *url.URL
		acs         *url.URL
		issuer      *url.URL
		metadata    *url.URL
		cfgOverride func(*saml.Config)
		expectedErr string
	}{
		{
			name:        "When all URLs are provided",
			entityID:    entityID,
			acs:         acs,
			issuer:      issuer,
			metadata:    metadata,
			expectedErr: "",
		},
		{
			name:        "When there is no entity ID provided",
			acs:         acs,
			issuer:      issuer,
			metadata:    metadata,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: EntityID not set: invalid parameter",
		},
		{
			name:        "When there is no ACS URL provided",
			entityID:    entityID,
			issuer:      issuer,
			metadata:    metadata,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: ACS URL not set: invalid parameter",
		},
		{
			name:        "When there is no issuer provided",
			acs:         acs,
			entityID:    entityID,
			metadata:    metadata,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: Issuer not set: invalid parameter",
		},
		{
			name:        "When there is no metadata URL provided",
			acs:         acs,
			entityID:    entityID,
			issuer:      issuer,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: Metadata URL not set: invalid parameter",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(_ *testing.T) {
			got, err := saml.NewConfig(
				c.entityID,
				c.acs,
				c.issuer,
				c.metadata,
			)

			if c.expectedErr != "" {
				r.ErrorContains(err, c.expectedErr)
			} else {
				r.NoError(err)

				r.Equal(got.EntityID.String(), "http://test.me/entity")
				r.Equal(got.AssertionConsumerServiceURL.String(), "http://test.me/sso/acs")
				r.Equal(got.Issuer.String(), "http://test.me")
				r.Equal(got.MetadataURL.String(), "http://test.me/sso/metadata")

				r.NotNil(got.GenerateAuthRequestID)
				r.NotNil(got.ValidUntil)
			}
		})
	}
}

func Test_GenerateAuthRequestID(t *testing.T) {
	r := require.New(t)

	id, err := saml.GenerateAuthRequestID()
	r.NoError(err)

	r.Contains(id, "_")

	splitted := strings.Split(id, "_")

	_, err = uuid.ParseUUID(splitted[1])
	r.NoError(err)
}
