package ldap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/cap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Authenticate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
		testdirectory.NewGroup(t, "admin", []string{"eve"}, testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"})),
	}
	tokenGroups := map[string][]*gldap.Entry{
		"S-1-1": {
			testdirectory.NewGroup(t, "admin", []string{"alice"}),
		},
	}
	sidBytes, err := ldap.SIDBytes(1, 1)
	require.NoError(t, err)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"}, testdirectory.WithMembersOf(t, "admin"), testdirectory.WithTokenGroups(t, sidBytes))
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"eve"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}),
			testdirectory.WithMembersOf(t, "admin"))...,
	)
	td.SetUsers(users...)
	td.SetGroups(groups...)
	td.SetTokenGroups(tokenGroups)
	tests := []struct {
		name               string
		username           string
		password           string
		clientConfig       *ldap.ClientConfig
		opts               []ldap.Option
		wantGroups         []string
		wantUserAttributes []ldap.Attribute
		wantErr            bool
		wantErrIs          error
		wantErrContains    string
	}{
		{
			name:     "missing-username",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			wantErr:         true,
			wantErrIs:       ldap.ErrInvalidParameter,
			wantErrContains: "missing username",
		},
		{
			name:     "missing-password",
			username: "alice",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			wantErr:         true,
			wantErrIs:       ldap.ErrInvalidParameter,
			wantErrContains: "password cannot be of zero length if allow_empty_passwd_bind is not enabled",
		},
		{
			name:     "unable-to-connect",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", 65535)},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			wantErr:         true,
			wantErrContains: "failed to connect",
		},
		{
			name:     "failed-get-user-binddn",
			username: "invalid-name",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			wantErr:         true,
			wantErrContains: "discovery of user bind DN failed",
		},
		{
			name:     "success-with-anon-bind",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "success-with-user-attributes",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			opts: []ldap.Option{ldap.WithUserAttributes()},
			wantUserAttributes: []ldap.Attribute{
				{Name: "email", Vals: []string{"alice@example.com"}},
				{Name: "memberOf", Vals: []string{"admin"}},
				{Name: "name", Vals: []string{"alice"}},
				{Name: "password", Vals: []string{"password"}},
				{Name: "tokenGroups", Vals: []string{"\x01\x00\x00\x00\x00\x00\x00\x01"}},
			},
		},
		{
			name:     "success-with-groups-and-user-attributes",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			opts: []ldap.Option{ldap.WithGroups(), ldap.WithUserAttributes()},
			wantUserAttributes: []ldap.Attribute{
				{Name: "email", Vals: []string{"alice@example.com"}},
				{Name: "memberOf", Vals: []string{"admin"}},
				{Name: "name", Vals: []string{"alice"}},
				{Name: "password", Vals: []string{"password"}},
				{Name: "tokenGroups", Vals: []string{"\x01\x00\x00\x00\x00\x00\x00\x01"}},
			},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "success-with-user-filter",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
				UserFilter:  "({{.UserAttr}}={{.Username}})",
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "failed-with-invalid-user-filter",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
				UserFilter:  "({{.BadFilter}}={{.Username}})",
			},
			opts:            []ldap.Option{ldap.WithGroups()},
			wantGroups:      []string{groups[0].DN},
			wantErr:         true,
			wantErrContains: "search failed due to template parsing error",
		},
		{
			name:     "success-with-anon-bind-token-groups",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:           []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate:    td.Cert(),
				DiscoverDN:     true,
				UserDN:         testdirectory.DefaultUserDN,
				GroupDN:        testdirectory.DefaultGroupDN,
				UseTokenGroups: true,
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "success-with-anon-bind-upn-domain",
			username: "eve",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
				UPNDomain:   "example.com",
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "success-with-binddn",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate:  td.Cert(),
				DiscoverDN:   true,
				UserDN:       testdirectory.DefaultUserDN,
				GroupDN:      testdirectory.DefaultGroupDN,
				BindDN:       fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "bob", testdirectory.DefaultUserDN),
				BindPassword: "password",
			},
			opts:       []ldap.Option{ldap.WithGroups(), ldap.WithUserAttributes()},
			wantGroups: []string{groups[0].DN},
			wantUserAttributes: []ldap.Attribute{
				{Name: "email", Vals: []string{"alice@example.com"}},
				{Name: "memberOf", Vals: []string{"admin"}},
				{Name: "name", Vals: []string{"alice"}},
				{Name: "password", Vals: []string{"password"}},
				{Name: "tokenGroups", Vals: []string{"\x01\x00\x00\x00\x00\x00\x00\x01"}},
			},
		},
		{
			name:     "failed-bind-aka-authentication",
			username: "alice",
			password: "invalid-password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
			},
			opts:            []ldap.Option{ldap.WithGroups()},
			wantGroups:      []string{groups[0].DN},
			wantErr:         true,
			wantErrContains: "unable to bind user",
		},
		{
			name:     "success-with-anon-bind-anon-group-search",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:                 []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate:          td.Cert(),
				DiscoverDN:           true,
				UserDN:               testdirectory.DefaultUserDN,
				GroupDN:              testdirectory.DefaultGroupDN,
				AnonymousGroupSearch: true,
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client, err := ldap.NewClient(testCtx, tc.clientConfig)
			defer func() { client.Close(testCtx) }()
			require.NoError(err)
			authResult, err := client.Authenticate(testCtx, tc.username, tc.password, tc.opts...)
			if authResult != nil && len(authResult.Warnings) > 0 {
				t.Log(authResult.Warnings)
			}
			if tc.wantErr {
				require.Error(err)
				assert.Nil(authResult)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(authResult)
			assert.Equal(tc.wantUserAttributes, authResult.UserAttributes)
			assert.Equal(tc.wantGroups, authResult.Groups)
		})
	}
	t.Run("allow-empty-passwords", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		client, err := ldap.NewClient(testCtx, &ldap.ClientConfig{
			URLs:                    []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificate:             td.Cert(),
			AllowEmptyPasswordBinds: true,
			DiscoverDN:              true,
			UserDN:                  testdirectory.DefaultUserDN,
			GroupDN:                 testdirectory.DefaultGroupDN,
		})
		defer func() { client.Close(testCtx) }()
		require.NoError(err)

		authResult, err := client.Authenticate(testCtx, "alice", "")
		require.NoError(err)
		assert.NotNil(authResult)
	})
	t.Run("allow-empty-passwords", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// do not allow anon binds
		td2 := testdirectory.Start(t,
			testdirectory.WithLogger(t, logger),
		)
		td2.SetUsers(users...)
		td2.SetGroups(groups...)
		td2.SetTokenGroups(tokenGroups)
		client, err := ldap.NewClient(testCtx, &ldap.ClientConfig{
			URLs:                 []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td2.Port())},
			Certificate:          td2.Cert(),
			DiscoverDN:           true,
			UserDN:               testdirectory.DefaultUserDN,
			GroupDN:              testdirectory.DefaultGroupDN,
			AnonymousGroupSearch: true,
			BindDN:               fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "bob", testdirectory.DefaultUserDN),
			BindPassword:         "password",
		})
		defer func() { client.Close(testCtx) }()
		require.NoError(err)
		authResult, err := client.Authenticate(testCtx, "alice", "password", ldap.WithGroups())
		require.Error(err)
		assert.Contains(err.Error(), "group search anonymous bind")
		assert.Nil(authResult)
	})
}
