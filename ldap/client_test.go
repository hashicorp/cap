package ldap

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_NewClient(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t, testdirectory.WithMTLS(t), testdirectory.WithLogger(t, logger))
	tests := []struct {
		name            string
		conf            *ClientConfig
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-config",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing config",
		},
		{
			name: "client-cert-without-key",
			conf: &ClientConfig{
				ClientTLSCert: td.ClientCert(),
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "both client_tls_cert and client_tls_key must be set in configuration",
		},
		{
			name: "client-key-without-cert",
			conf: &ClientConfig{
				ClientTLSKey: td.ClientKey(),
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "both client_tls_cert and client_tls_key must be set in configuration",
		},
		{
			name: "invalid-tls-min",
			conf: &ClientConfig{
				TLSMinVersion: "invalid-tls-version",
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "invalid 'tls_min_version' in config",
		},
		{
			name: "invalid-tls-max",
			conf: &ClientConfig{
				TLSMaxVersion: "invalid-tls-version",
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "invalid 'tls_max_version' in config",
		},
		{
			name: "tls-max-less-than-min",
			conf: &ClientConfig{
				TLSMinVersion: "tls12",
				TLSMaxVersion: "tls10",
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "'tls_max_version' must be greater than or equal to 'tls_min_version'",
		},
		{
			name: "invalid-cert",
			conf: &ClientConfig{
				Certificate: "invalid-cert",
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "failed to parse server tls cert",
		},
		{
			name: "invalid-key-pair",
			conf: &ClientConfig{
				ClientTLSKey:  "invalid-key",
				ClientTLSCert: "invalid-cert",
			},
			wantErr:         true,
			wantErrContains: "failed to parse client X509 key pair",
		},
		{
			name: "valid-key-pair",
			conf: &ClientConfig{
				URLs:          []string{"localhost"},
				TLSMinVersion: "tls12",
				TLSMaxVersion: "tls13",
				Certificate:   td.Cert(),
				ClientTLSKey:  td.ClientKey(),
				ClientTLSCert: td.ClientCert(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewClient(testCtx, tc.conf)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(c)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(c)
			if tc.conf == nil {
				assert.Equal([]string{DefaultURL}, c.conf.URLs)
				assert.Equal(DefaultGroupAttr, c.conf.GroupAttr)
				assert.Equal(DefaultGroupFilter, c.conf.GroupFilter)
				assert.Equal(DefaultTLSMinVersion, c.conf.TLSMinVersion)
				assert.Equal(DefaultTLSMaxVersion, c.conf.TLSMaxVersion)
			} else {

			}
		})
	}
}

func TestClient_connect(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	tdTLS := testdirectory.Start(t, testdirectory.WithLogger(t, logger))
	tdNonTLS := testdirectory.Start(t, testdirectory.WithNoTLS(t), testdirectory.WithLogger(t, logger))
	startTLSPool := x509.NewCertPool()
	require.True(t, startTLSPool.AppendCertsFromPEM([]byte(tdNonTLS.Cert())))
	tests := []struct {
		name            string
		conf            *ClientConfig
		afterNewClient  func(*Client)
		connectOpts     []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-conf",
			conf: &ClientConfig{
				URLs: []string{fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())},
			},
			afterNewClient:  func(c *Client) { c.conf = nil },
			wantErr:         true,
			wantErrContains: "missing configuration",
			wantErrIs:       ErrInternal,
		},
		{
			name: "missing-urls",
			conf: &ClientConfig{
				URLs: []string{fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())},
			},
			afterNewClient:  func(c *Client) { c.conf.URLs = nil },
			wantErr:         true,
			wantErrContains: "missing both configuration and optional LDAP URLs",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name: "failed-to-parse-urls",
			conf: &ClientConfig{
				// leading space
				URLs: []string{" ldap://127.0.0.1:"},
			},
			wantErr:         true,
			wantErrContains: "error parsing url",
		},
		{
			name: "invalid-urls",
			conf: &ClientConfig{
				URLs: []string{"badscheme://127.0.0.1:"},
			},
			wantErr:         true,
			wantErrContains: "invalid LDAP scheme in url",
		},
		{
			name: "error-connecting",
			conf: &ClientConfig{
				// leading space
				URLs: []string{"ldap://127.0.0.1:"},
			},
			wantErr:         true,
			wantErrContains: "error connecting to host",
		},
		{
			name: "tls",
			conf: &ClientConfig{
				Certificate: tdTLS.Cert(),
				URLs:        []string{fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())},
			},
		},
		{
			name: "tls-with-all-opts",
			conf: &ClientConfig{
				Certificate:    tdTLS.Cert(),
				URLs:           []string{fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())},
				RequestTimeout: 2,
			},
			connectOpts: []Option{
				WithURLs(fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())),
			},
		},
		{
			name: "non-tls",
			conf: &ClientConfig{
				Certificate: tdTLS.Cert(),
				URLs:        []string{fmt.Sprintf("ldap://localhost:%d", tdNonTLS.Port())},
			},
		},
		{
			name: "start-tls",
			conf: &ClientConfig{
				Certificate: tdNonTLS.Cert(),
				URLs:        []string{fmt.Sprintf("ldap://localhost:%d", tdNonTLS.Port())},
				StartTLS:    true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewClient(testCtx, tc.conf)
			require.NoError(err)
			if tc.afterNewClient != nil {
				tc.afterNewClient(c)
			}
			err = c.connect(testCtx, tc.connectOpts...)
			defer func() { c.Close(testCtx) }()
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(c.conn)
		})
	}

	// this test won't run if there's already a service listening on port 389,
	// but on most systems and in CI it will run and it allows us to test
	// connecting to a URL without a port
	t.Run("389", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		logger := hclog.New(&hclog.LoggerOptions{
			Name:  "test-logger",
			Level: hclog.Error,
		})
		ln, err := net.Listen("tcp", ":"+"389")
		ln.Close()
		if err == nil {
			_ = testdirectory.Start(t, testdirectory.WithNoTLS(t), testdirectory.WithLogger(t, logger), testdirectory.WithPort(t, 389))
			c, err := NewClient(testCtx, &ClientConfig{
				URLs: []string{"ldap://127.0.0.1"},
			})
			require.NoError(err)
			err = c.connect(testCtx)
			defer func() { c.Close(testCtx) }()
			assert.NoError(err)
		}
	})
}

func Test_sidBytesToString(t *testing.T) {
	testcases := map[string][]byte{
		"S-1-5-21-2127521184-1604012920-1887927527-72713": {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xA0, 0x65, 0xCF, 0x7E, 0x78, 0x4B, 0x9B, 0x5F, 0xE7, 0x7C, 0x87, 0x70, 0x09, 0x1C, 0x01, 0x00},
		"S-1-1-0": {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		"S-1-5":   {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
		"S-1-6":   func() []byte { b, err := SIDBytes(1, 6); require.NoError(t, err); return b }(),
		"S-2-22":  func() []byte { b, err := SIDBytes(2, 22); require.NoError(t, err); return b }(),
	}

	for answer, test := range testcases {
		res, err := sidBytesToString(test)
		if err != nil {
			t.Errorf("Failed to convert %#v: %s", test, err)
		} else if answer != res {
			t.Errorf("Failed to convert %#v: %s != %s", test, res, answer)
		}
	}
}

func Test_validateCertificate(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t, testdirectory.WithMTLS(t), testdirectory.WithLogger(t, logger))

	tests := []struct {
		name            string
		pemBlock        []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-pem-block",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing certificate pem block",
		},
		{
			name: "invalid-pem-block",
			pemBlock: []byte(
				`-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
-----END CERTIFICATE-----`),
			wantErr:         true,
			wantErrContains: "failed to parse certificate",
		},
		{
			name:     "success",
			pemBlock: []byte(td.Cert()),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := validateCertificate(tc.pemBlock)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
