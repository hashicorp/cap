// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func TestClient_renderUserSearchFilter(t *testing.T) {
	t.Parallel()
	// just ensure that rendered filters are properly escaped
	testCtx := context.Background()
	tests := []struct {
		name        string
		conf        *ClientConfig
		userName    string
		want        string
		errContains string
	}{
		{
			name:     "valid-default",
			userName: "alice",
			conf: &ClientConfig{
				URLs: []string{"localhost"},
			},
			want: "(cn=alice)",
		},
		{
			name:     "escaped-malicious-filter",
			userName: "foo@example.com)((((((((((((((((((((((((((((((((((((((userPrincipalName=foo",
			conf: &ClientConfig{
				URLs:       []string{"localhost"},
				UPNDomain:  "example.com",
				UserFilter: "(&({{.UserAttr}}={{.Username}})({{.UserAttr}}=admin@example.com))",
			},
			want: "(&(userPrincipalName=foo@example.com\\29\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28\\28userPrincipalName=foo@example.com)(userPrincipalName=admin@example.com))",
		},
		{
			name:     "bad-filter-unclosed-action",
			userName: "alice",
			conf: &ClientConfig{
				URLs:       []string{"localhost"},
				UserFilter: "hello{{range",
			},
			errContains: "search failed due to template compilation error",
		},
		{
			name: "missing-username",
			conf: &ClientConfig{
				URLs: []string{"localhost"},
			},
			errContains: "missing username",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewClient(testCtx, tc.conf)
			require.NoError(err)

			f, err := c.renderUserSearchFilter(tc.userName)
			if tc.errContains != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.errContains)
				return
			}
			require.NoError(err)
			assert.NotEmpty(f)
			assert.Equal(tc.want, f)
		})
	}
}

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
		want            *Client
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
			name: "valid-tls-max",
			conf: &ClientConfig{
				TLSMaxVersion: "tls13",
			},
			want: &Client{
				conf: &ClientConfig{
					URLs:          []string{"ldaps://127.0.0.1:686"},
					DerefAliases:  "never",
					GroupFilter:   "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
					GroupAttr:     "cn",
					UserAttr:      "cn",
					TLSMinVersion: "tls12",
					TLSMaxVersion: "tls13",
				},
			},
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
				Certificates: []string{"invalid-cert"},
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
				Certificates:  []string{td.Cert()},
				ClientTLSKey:  td.ClientKey(),
				ClientTLSCert: td.ClientCert(),
			},
			want: &Client{
				conf: &ClientConfig{
					URLs:          []string{"localhost"},
					DerefAliases:  "never",
					GroupFilter:   "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
					GroupAttr:     "cn",
					UserAttr:      "cn",
					TLSMinVersion: "tls12",
					TLSMaxVersion: "tls13",
					Certificates:  []string{td.Cert()},
					ClientTLSKey:  td.ClientKey(),
					ClientTLSCert: td.ClientCert(),
				},
			},
		},
		{
			name: "invalid-deref-aliases",
			conf: &ClientConfig{
				URLs:         []string{"localhost"},
				DerefAliases: "invalid",
			},
			wantErr:         true,
			wantErrContains: `invalid dereference_aliases "invalid"`,
		},
		{
			name: "default-deref-aliases",
			conf: &ClientConfig{
				URLs: []string{"localhost"},
			},
			want: &Client{
				conf: &ClientConfig{
					URLs:          []string{"localhost"},
					DerefAliases:  "never",
					GroupFilter:   "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
					GroupAttr:     "cn",
					UserAttr:      "cn",
					TLSMinVersion: "tls12",
					TLSMaxVersion: "tls13",
				},
			},
		},
		{
			name: "valid-deref-aliases",
			conf: &ClientConfig{
				URLs:         []string{"localhost"},
				DerefAliases: "always",
			},
			want: &Client{
				conf: &ClientConfig{
					URLs:          []string{"localhost"},
					DerefAliases:  "always",
					GroupFilter:   "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
					GroupAttr:     "cn",
					UserAttr:      "cn",
					TLSMinVersion: "tls12",
					TLSMaxVersion: "tls13",
				},
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
			}
			if tc.want != nil {
				assert.Equal(tc.want, c)
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
			name: "error-ldap-timeout",
			conf: &ClientConfig{
				RequestTimeout: 1,
				// invalid-port on ldap (non-tls) scheme
				URLs: []string{fmt.Sprintf("ldap://ldap.forumsys.com:%d", freePort(t))},
			},
			wantErr:         true,
			wantErrContains: "i/o timeout",
		},
		{
			name: "error-ldaps-timeout",
			conf: &ClientConfig{
				// invalid-port on ldaps (tls) scheme
				RequestTimeout: 1,
				URLs:           []string{fmt.Sprintf("ldaps://ldap.forumsys.com:%d", freePort(t))},
			},
			wantErr:         true,
			wantErrContains: "i/o timeout",
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
				Certificates: []string{tdTLS.Cert()},
				URLs:         []string{fmt.Sprintf("ldaps://localhost:%d", tdTLS.Port())},
			},
		},
		{
			name: "tls-with-all-opts",
			conf: &ClientConfig{
				Certificates:   []string{tdTLS.Cert()},
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
				Certificates: []string{tdTLS.Cert()},
				URLs:         []string{fmt.Sprintf("ldap://localhost:%d", tdNonTLS.Port())},
			},
		},
		{
			name: "start-tls",
			conf: &ClientConfig{
				Certificates: []string{tdNonTLS.Cert()},
				URLs:         []string{fmt.Sprintf("ldap://localhost:%d", tdNonTLS.Port())},
				StartTLS:     true,
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
	t.Run("3389", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		logger := hclog.New(&hclog.LoggerOptions{
			Name:  "test-logger",
			Level: hclog.Error,
		})
		if ln, err := net.Listen("tcp", ":"+"3389"); err == nil {
			ln.Close()
			_ = testdirectory.Start(t, testdirectory.WithNoTLS(t), testdirectory.WithLogger(t, logger), testdirectory.WithPort(t, 3389))
			c, err := NewClient(testCtx, &ClientConfig{
				URLs: []string{"ldap://127.0.0.1:3389"},
			})
			require.NoError(err)
			err = c.connect(testCtx)
			defer func() { c.Close(testCtx) }()
			assert.NoError(err)
		} else {
			t.Logf("warning: failed to listen on port 3389, err=%s", err)
		}
	})
}

func TestClient_getUserBindDN(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(nil,
		testdirectory.WithDefaults(nil, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"eve"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}))...,
	)
	// Set up a duplicated user to test the case where the search returns multiple users
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"mallory", "mallory"},
		)...,
	)
	td.SetUsers(users...)

	cases := map[string]struct {
		conf     *ClientConfig
		username string

		want            string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		"fail: missing username": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
			},
			username: "",

			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing username",
		},
		"fail: missing all of discoverdn, binddn, bindpass, upndomain, userdn": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
			},
			username: "alice",

			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "cannot derive UserBindDN based on config (see combination of: discoverdn, binddn, bindpass, upndomain, userdn)",
		},
		"fail: search fails to find user": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				DiscoverDN:   true,
			},
			username: "nonexistent",

			wantErr:         true,
			wantErrContains: "LDAP search for binddn failed",
		},
		"fail: search returns multiple users": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				DiscoverDN:   true,
			},
			username: "mallory",

			wantErr:         true,
			wantErrContains: "LDAP search for binddn 0 or not unique",
		},
		"fail: invalid search filter": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				DiscoverDN:   true,
				UserFilter:   "({{.BadFilter}}={{.Username}})",
			},
			username: "alice",

			wantErr:         true,
			wantErrContains: "search failed due to template parsing error",
		},
		"success: discoverdn": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				DiscoverDN:   true,
			},
			username: "alice",

			want: "cn=alice,ou=people,dc=example,dc=org",
		},
		"success: binddn and bindpass": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				BindDN:       "cn=bob,ou=people,dc=example,dc=org",
				BindPassword: "password",
			},
			username: "alice",

			want: "cn=alice,ou=people,dc=example,dc=org",
		},
		"success: upndomain": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				UPNDomain:    "example.com",
			},
			username: "eve",

			want: "eve@example.com",
		},
		"success: userdn": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				UserDN:       testdirectory.DefaultUserDN,
			},
			username: "alice",

			want: "cn=alice,ou=people,dc=example,dc=org",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewClient(testCtx, tc.conf)
			require.NoError(err)
			err = c.connect(testCtx)
			require.NoError(err)
			defer func() { c.Close(testCtx) }()
			got, err := c.getUserBindDN(tc.username)
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
			assert.Equal(tc.want, got)
		})
	}
}

func TestClient_getUserDN(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(nil,
		testdirectory.WithDefaults(nil, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"eve"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}))...,
	)
	// Set up a duplicated user to test the case where the search returns multiple users
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"mallory", "mallory"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}),
		)...,
	)
	td.SetUsers(users...)

	tests := map[string]struct {
		conf     *ClientConfig
		bindDN   string
		username string

		want            string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		"fail: missing bind dn": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
			},
			bindDN:   "",
			username: "alice",

			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing bind dn",
		},
		"fail: missing username": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
			},
			bindDN:   fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "bob", testdirectory.DefaultUserDN),
			username: "",

			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing username",
		},
		"fail: upn domain search fails to find user": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				UPNDomain:    "example.com",
			},
			bindDN:   "userPrincipalName=nonexistent@example.com,ou=people,dc=example,dc=org",
			username: "nonexistent",

			wantErr:         true,
			wantErrContains: "LDAP search failed for detecting user",
		},
		"fail: upn domain search returns multiple users": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				UPNDomain:    "example.com",
			},
			bindDN:   "userPrincipalName=mallory@example.com,ou=people,dc=example,dc=org",
			username: "mallory",

			wantErr:         true,
			wantErrContains: "LDAP search for user 0 or not unique",
		},
		"success: no upn domain": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
			},
			bindDN:   "cn=alice,ou=people,dc=example,dc=org",
			username: "alice",

			want: "cn=alice,ou=people,dc=example,dc=org",
		},
		"success: upn domain with samaccountname": {
			conf: &ClientConfig{
				URLs:                      []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates:              []string{td.Cert()},
				UPNDomain:                 "example.com",
				EnableSamaccountnameLogin: true,
			},
			bindDN:   "userPrincipalName=eve@example.com,ou=people,dc=example,dc=org",
			username: "eve",

			want: "userPrincipalName=eve@example.com,ou=people,dc=example,dc=org",
		},
		"success: upn domain without samaccountname": {
			conf: &ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificates: []string{td.Cert()},
				UPNDomain:    "example.com",
			},
			bindDN:   "userPrincipalName=eve@example.com,ou=people,dc=example,dc=org",
			username: "eve",

			want: "userPrincipalName=eve@example.com,ou=people,dc=example,dc=org",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewClient(testCtx, tc.conf)
			require.NoError(err)
			err = c.connect(testCtx)
			require.NoError(err)
			defer func() { c.Close(testCtx) }()
			got, err := c.getUserDN(tc.bindDN, tc.username)
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
			assert.Equal(tc.want, got)
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

func freePort(t *testing.T) int {
	t.Helper()
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
