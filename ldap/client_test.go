package ldap

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_NewClient(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	td := StartTestDirectory(t, WithTestMTLS())
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
	tdTLS := StartTestDirectory(t)
	tdNonTLS := StartTestDirectory(t, WithTestNoTLS())
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
			name: "invalid-urls",
			conf: &ClientConfig{
				URLs: []string{"badscheme://127.0.0.1:"},
			},
			wantErr:         true,
			wantErrContains: "invalid LDAP scheme in url",
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
