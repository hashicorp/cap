package oidc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCaPem = `
-----BEGIN CERTIFICATE-----
MIIGkDCCBXigAwIBAgIQAvNWnNS26r7th/gsZC85WDANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0xNzExMjkwMDAwMDBaFw0yMTAxMTQxMjAwMDBa
MIGkMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxML
TG9zIEFuZ2VsZXMxPDA6BgNVBAoTM0ludGVybmV0IENvcnBvcmF0aW9uIGZvciBB
c3NpZ25lZCBOYW1lcyBhbmQgTnVtYmVyczEWMBQGA1UECxMNSVQgT3BlcmF0aW9u
czEUMBIGA1UEAwwLKi5pY2Fubi5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDHa33ZEtDn3USf6hfrSMx2hfpL+ji5q/g9JrnoSbuJG9Vrzw4sOAit
uBrpN5e6/w1AAPEPKH+YJdJgVhTx/BKhQtgidkayYV4hNWN/AYpgkRcTN6raNtaU
q4NwmC2tmClRPeRUzy1aiJ7vCKyLaoClneVrLS5hD47QYbfjbhvDCSrtu64hDFkS
B1ZhplSCQpqxLXct6EuX/z7ArE3c676Ds1MxbbbmPUiQ1CsBMnMt5UfPhiTzqFm3
zCFHv99c9Gg3YfxjfWUQSIe6emevC/YBbi3mwhmpC7d5TJjzokuksgn9d9jhdjG3
wZ3pqSdtqSjRjgvLP5Wo3F7UPVLA+Js2It1N8tLCbcWM6/+Le810F+eLMkEGnB6K
VGqmj3NXzkO0+mCA2LDebsgFgDBsOzmY2k4tH9zi1m7/LsByVvMTpGxuvZ6+Ypvu
8vbu8JvQuZ6impR0WL/NTgYsmP0uW+uOXO8qwog1ZKyWwDbcN0greWwxIefyq50t
4m9SzB6dmO8asp1+hu3aULHOsFL1bRuCP84nEca3bwCUae1C9AiHx3z03XpPdGIy
mXxFHj7B9gs5Fu6bBfYF0eBfTF/4mMrJePDmfLChMGjp9qpqRFN7dX8bMgCJutKL
H+huy3L11VQ7hWAV9CFN2UflZG1t6Nf/2z3c60uxhYZCQ5+pMDsOmQIDAQABo4IB
7zCCAeswHwYDVR0jBBgwFoAUUWj/kK8CB3U8zNllZGKiErhZcjswHQYDVR0OBBYE
FB+KEPVsfdhKkgVbiRlpHCzb4Cy9MCEGA1UdEQQaMBiCCyouaWNhbm4ub3Jngglp
Y2Fubi5vcmcwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5j
b20vc2hhMi1oYS1zZXJ2ZXItZzYuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdp
Y2VydC5jb20vc2hhMi1oYS1zZXJ2ZXItZzYuY3JsMEwGA1UdIARFMEMwNwYJYIZI
AYb9bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9D
UFMwCAYGZ4EMAQICMIGDBggrBgEFBQcBAQR3MHUwJAYIKwYBBQUHMAGGGGh0dHA6
Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBNBggrBgEFBQcwAoZBaHR0cDovL2NhY2VydHMu
ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkhpZ2hBc3N1cmFuY2VTZXJ2ZXJDQS5j
cnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMUUQhWco7YunHRnQ
rm9KSLhCPozZlN9jdh553aRREDm6rizIdPfg8ISD1i3890u83iRYaHEVBpScecwR
dtBodNV/pWZCq+QmT71bk/Pwd+ZHpS3ydWJ2bde2dGk3crmlIdUzDYuPhf9tDsnr
jO6SVm8b6D+lpVU70p3InuHD2UB7IWiSIoH4U8nMJ+/sPp4+mK+00Thf+9rij6qe
Jso1E9ZBQ5Ak+GSAlyEWTKMFvqQqw0wbkomkhDOSy/qTYboxkyK4ExpiQQ2mrzdY
xP5W2sA5fUX2xkXBV7TY/UwrwVBoWiIrjygBQLy0OHOHEGE1hl6fGA7DcFO7mrw2
S3IprA==
-----END CERTIFICATE-----`

func TestClientSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = RedactedClientSecret
		secret := ClientSecret("bob's phone number")
		assert.Equalf(want, secret.String(), "ClientSecret.String() = %v, want %v", secret.String(), want)
	})
}

func TestClientSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, RedactedClientSecret)
		secret := ClientSecret("bob's phone number")
		got, err := secret.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "ClientSecret.MarshalJSON() = %s, want %s", got, want)
	})
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	type args struct {
		issuer       string
		clientId     string
		clientSecret ClientSecret
		supported    []Alg
		redirectUrl  string
		opt          []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *Config
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-with-all-valid-opts",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
				opt: []Option{
					WithAudiences("YOUR_AUD1", "YOUR_AUD2"),
					WithScopes("email", "profile"),
					WithProviderCA(testCaPem),
				},
			},
			want: &Config{
				Issuer:               "http://YOUR_ISSUER/",
				ClientId:             "YOUR_CLIENT_ID",
				ClientSecret:         "YOUR_CLIENT_SECRET",
				SupportedSigningAlgs: []Alg{RS512},
				RedirectUrl:          "http://YOUR_REDIRECT_URL",
				Audiences:            []string{"YOUR_AUD1", "YOUR_AUD2"},
				Scopes:               []string{"email", "profile"},
				ProviderCA:           testCaPem,
			},
		},
		{
			name: "empty-issuer",
			args: args{
				issuer:       "",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "bad-issuer-scheme",
			args: args{
				issuer:       "ldap://bad-scheme",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "bad-issuer-url",
			args: args{
				issuer:       "http://bad-url\\",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidIssuer,
		},
		{
			name: "empty-client-id",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-client-secret",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-algs",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    nil,
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "empty-redirect",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
		{
			name: "invalid-providerCA",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{RS512},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
				opt: []Option{
					WithProviderCA("bad certificate"),
				},
			},
			wantErr:   true,
			wantIsErr: ErrInvalidCACert,
		},
		{
			name: "invalid-alg",
			args: args{
				issuer:       "http://YOUR_ISSUER/",
				clientId:     "YOUR_CLIENT_ID",
				clientSecret: "YOUR_CLIENT_SECRET",
				supported:    []Alg{"bad alg"},
				redirectUrl:  "http://YOUR_REDIRECT_URL",
			},
			wantErr:   true,
			wantIsErr: ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewConfig(tt.args.issuer, tt.args.clientId, tt.args.clientSecret, tt.args.supported, tt.args.redirectUrl, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "wanted \"%s\" but got \"%s\"", tt.wantIsErr, err)
				return
			}
			require.NoError(err)
			assert.Equalf(tt.want, got, "NewConfig() = %v, want %v", got, tt.want)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	// Validate testing is covered by TestNewConfig() but we do have just more
	// more test to add here.
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		var c *Config
		err := c.Validate()
		assert.Truef(errors.Is(err, ErrNilParameter), "Config.Validate() = %v, want %v", err, ErrNilParameter)
	})
}

func Test_WithScopes(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithScopes("alice", "bob"))
	testOpts := configDefaults()
	testOpts.withScopes = []string{"alice", "bob"}
	assert.Equal(opts, testOpts)
}

func Test_WithAudiences(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithAudiences("alice", "bob"))
	testOpts := configDefaults()
	testOpts.withAudiences = []string{"alice", "bob"}
	assert.Equal(opts, testOpts)
}

func Test_WithProviderCA(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithProviderCA(testCaPem))
	testOpts := configDefaults()
	testOpts.withProviderCA = testCaPem
	assert.Equal(opts, testOpts)
}
