package ldap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/cap/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Authenticate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	td := ldap.StartTestDirectory(t,
		ldap.WithTestDirectoryDefaults(&ldap.TestDirectoryDefaults{AllowAnonymousBind: true}),
		// ldap.WithTestLogging(),
	)
	groups := []*ldap.TestEntry{
		ldap.TestGroup(t, "admin", []string{"alice"}),
		ldap.TestGroup(t, "admin", []string{"eve"}, ldap.WithTestDefaults(t, &ldap.TestDefaults{UPNDomain: "example.com"})),
	}
	tokenGroups := map[string][]*ldap.TestEntry{
		"S-1-1": {
			ldap.TestGroup(t, "admin", []string{"alice"}),
		},
	}
	sidBytes, err := ldap.SIDBytes(1, 1)
	require.NoError(t, err)
	users := ldap.TestUsers(t, []string{"alice", "bob"}, ldap.WithTestMembersOf(t, "admin"), ldap.WithTestTokenGroups(t, sidBytes))
	users = append(
		users,
		ldap.TestUsers(
			t,
			[]string{"eve"},
			ldap.WithTestDefaults(t, &ldap.TestDefaults{UPNDomain: "example.com"}),
			ldap.WithTestMembersOf(t, "admin"))...,
	)
	td.SetUsers(users...)
	td.SetGroups(groups...)
	td.SetTokenGroups(tokenGroups)
	tests := []struct {
		name         string
		username     string
		password     string
		clientConfig *ldap.ClientConfig
		opts         []ldap.Option
		wantErr      bool
		wantGroups   []string
	}{
		{
			name:     "success-with-anon-bind",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate: td.Cert(),
				DiscoverDN:  true,
				UserDN:      ldap.TestDefaultUserDN,
				GroupDN:     ldap.TestDefaultGroupDN,
			},
			opts:       []ldap.Option{ldap.WithGroups()},
			wantGroups: []string{groups[0].DN},
		},
		{
			name:     "success-with-anon-bind-token-groups",
			username: "alice",
			password: "password",
			clientConfig: &ldap.ClientConfig{
				URLs:           []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
				Certificate:    td.Cert(),
				DiscoverDN:     true,
				UserDN:         ldap.TestDefaultUserDN,
				GroupDN:        ldap.TestDefaultGroupDN,
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
				UserDN:      ldap.TestDefaultUserDN,
				GroupDN:     ldap.TestDefaultGroupDN,
				UPNDomain:   "example.com",
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
			}
			require.NoError(err)
			require.NotNil(authResult)
			assert.Equal(tc.wantGroups, authResult.Groups)
		})
	}

}
