// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package saml_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
)

func Test_NewConfig(t *testing.T) {
	t.Parallel()
	const (
		entityID = "http://test.me/entity"
		acs      = "http://test.me/sso/acs"
		metadata = "http://test.me/sso/metadata"
	)

	cases := []struct {
		name        string
		entityID    string
		acs         string
		issuer      string
		metadata    string
		opts        []saml.Option
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
		{
			name:     "valid-WithMetadataParameters",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: "https://samltest.id/idp/profile/Shibboleth/SSO",
					IDPCertificate:  testEncodedMetadataCert,
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
		},
		{
			name:     "err-WithMetadataParameters-empty",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{}),
			},
			expectedErr: "saml.Config.Validate: issuer not set",
		},
		{
			name:     "err-WithMetadataParameters-invalid-issuer",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          " https://samltest.id/idp", // extra space at the start makes it invalid
					SingleSignOnURL: "https://samltest.id/idp/profile/Shibboleth/SSO",
					IDPCertificate:  testEncodedMetadataCert,
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: "provided Issuer is not a valid URL",
		},
		{
			name:     "err-WithMetadataParameters-missing-sso-url",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: "",
					IDPCertificate:  testEncodedMetadataCert,
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: "SSO URL not set",
		},
		{
			name:     "err-WithMetadataParameters-invalid-sso-url",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: " https://samltest.id/idp/profile/Shibboleth/SSO", // extra space at the start makes it invalid
					IDPCertificate:  testEncodedMetadataCert,
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: "provided SSO URL is not a valid URL",
		},
		{
			name:     "err-WithMetadataParameters-missing-cert",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: "https://samltest.id/idp/profile/Shibboleth/SSO",
					IDPCertificate:  "",
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: "no certificate found",
		},
		{
			name:     "err-WithMetadataParameters-extra-data",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: "https://samltest.id/idp/profile/Shibboleth/SSO",
					IDPCertificate:  testEncodedMetadataCert + "\nextra bits",
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: "extra data found after certificate",
		},
		{
			name:     "err-WithMetadataParameters-invalid-block-identifier",
			entityID: entityID,
			acs:      acs,
			metadata: metadata,
			opts: []saml.Option{
				saml.WithMetadataParameters(saml.MetadataParameters{
					Issuer:          "https://samltest.id/idp",
					SingleSignOnURL: "https://samltest.id/idp/profile/Shibboleth/SSO",
					IDPCertificate:  testEncodedMetadataCertWithInvalidBlockIdentifier,
					Binding:         core.ServiceBindingHTTPPost,
				}),
			},
			expectedErr: `wrong block type found: "PRIVATE KEY"`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := require.New(t)
			got, err := saml.NewConfig(
				c.entityID,
				c.acs,
				c.metadata,
				c.opts...,
			)

			if c.expectedErr != "" {
				r.ErrorContains(err, c.expectedErr)
				return
			}
			r.NoError(err)

			r.Equal(got.EntityID, "http://test.me/entity")
			r.Equal(got.AssertionConsumerServiceURL, "http://test.me/sso/acs")
			r.Equal(got.MetadataURL, "http://test.me/sso/metadata")

			r.NotNil(got.GenerateAuthRequestID)
			r.NotNil(got.ValidUntil)
		})
	}
}

func Test_GenerateAuthRequestID(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	id, err := saml.DefaultGenerateAuthRequestID()
	r.NoError(err)

	r.Contains(id, "_")

	splitted := strings.Split(id, "_")

	_, err = uuid.ParseUUID(splitted[1])
	r.NoError(err)
}

const testEncodedMetadataCert = `
-----BEGIN CERTIFICATE-----
MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEB
CwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4
MDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFKs71ufbQwoQoW7qkNAJRIANGA4iM0
ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyjxj0uJ4lArgkr4AOE
jj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVNc1kl
bN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF
/cL5fOpdVa54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8n
spXiH/MZW8o2cqWRkrw3MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0G
A1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE4k2ZNTA0BgNVHREELTArggtzYW1sdGVz
dC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF
AAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3YaMb2RSn
7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHT
TNiLArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nbl
D1JJKSQ3AdhxK/weP3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcU
ZOpx4swtgGdeoSpeRyrtMvRwdcciNBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu
3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==
-----END CERTIFICATE-----
`

const testEncodedMetadataCertWithInvalidBlockIdentifier = `
-----BEGIN PRIVATE KEY-----
MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEB
CwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4
MDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFKs71ufbQwoQoW7qkNAJRIANGA4iM0
ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyjxj0uJ4lArgkr4AOE
jj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVNc1kl
bN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF
/cL5fOpdVa54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8n
spXiH/MZW8o2cqWRkrw3MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0G
A1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE4k2ZNTA0BgNVHREELTArggtzYW1sdGVz
dC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF
AAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3YaMb2RSn
7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHT
TNiLArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nbl
D1JJKSQ3AdhxK/weP3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcU
ZOpx4swtgGdeoSpeRyrtMvRwdcciNBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu
3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==
-----END PRIVATE KEY-----
`
