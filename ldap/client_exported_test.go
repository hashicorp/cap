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
	td := testdirectory.StartDirectory(t,
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
				UserDN:      testdirectory.DefaultUserDN,
				GroupDN:     testdirectory.DefaultGroupDN,
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
