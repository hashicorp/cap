package saml_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
)

func Test_NewConfig(t *testing.T) {
	entityID := "http://test.me/entity"
	acs := "http://test.me/sso/acs"
	metadata := "http://test.me/sso/metadata"

	cases := []struct {
		name        string
		entityID    string
		acs         string
		issuer      string
		metadata    string
		cfgOverride func(*saml.Config)
		expectedErr string
	}{
		{
			name:        "When all URLs are provided",
			entityID:    entityID,
			acs:         acs,
			metadata:    metadata,
			expectedErr: "",
		},
		{
			name:        "When there is no entity ID provided",
			acs:         acs,
			metadata:    metadata,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: EntityID not set: invalid parameter",
		},
		{
			name:        "When there is no ACS URL provided",
			entityID:    entityID,
			metadata:    metadata,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: ACS URL not set: invalid parameter",
		},
		{
			name:        "When there is no metadata URL provided",
			acs:         acs,
			entityID:    entityID,
			expectedErr: "saml.NewConfig: invalid provider config: saml.Config.Validate: One of MetadataURL, MetadataXML, or MetadataParameters must be set: invalid parameter",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := require.New(t)
			got, err := saml.NewConfig(
				c.entityID,
				c.acs,
				c.metadata,
			)

			if c.expectedErr != "" {
				r.ErrorContains(err, c.expectedErr)
			} else {
				r.NoError(err)

				r.Equal(got.EntityID, "http://test.me/entity")
				r.Equal(got.AssertionConsumerServiceURL, "http://test.me/sso/acs")
				r.Equal(got.MetadataURL, "http://test.me/sso/metadata")

				r.NotNil(got.GenerateAuthRequestID)
				r.NotNil(got.ValidUntil)
			}
		})
	}
}

func Test_GenerateAuthRequestID(t *testing.T) {
	r := require.New(t)

	id, err := saml.DefaultGenerateAuthRequestID()
	r.NoError(err)

	r.Contains(id, "_")

	splitted := strings.Split(id, "_")

	_, err = uuid.ParseUUID(splitted[1])
	r.NoError(err)
}
