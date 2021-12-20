package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StartTestDirectory(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testEntries := TestUsers(t, []string{"alice"}, WithTestDefaults(t, &TestDefaults{UserAttr: "uid"}))
	t.Run("tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testFreePort(t)
		td := StartTestDirectory(
			t,
			WithTestPort(port),
			WithTestDirectoryDefaults(&TestDirectoryDefaults{
				Users: testEntries,
			}),
		)
		assert.Equal(port, td.Port())

		c, err := NewClient(testCtx, &ClientConfig{
			URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificate: td.Cert(),
		})
		require.NoError(err)
		err = c.connect(testCtx)
		defer c.Close(testCtx)
		require.NoError(err)

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN: TestDefaultUserDN,
			Filter: fmt.Sprintf("(uid=%s)", EscapeValue("alice*")),
		})
		require.NoError(err)
		require.Len(result.Entries, 1)
		assert.Equal("uid=alice,"+TestDefaultUserDN, result.Entries[0].DN)
		for _, e := range result.Entries {
			t.Log("***")
			t.Log(e.DN)
			for _, attr := range e.Attributes {
				t.Log(attr.Name, attr.Values)
			}
		}
		c.Close(testCtx)
	})
	t.Run("non-tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testFreePort(t)
		td := StartTestDirectory(
			t,
			WithTestPort(port),
			WithTestNoTLS(),
			WithTestDirectoryDefaults(&TestDirectoryDefaults{
				Users: testEntries,
			}),
		)
		assert.Equal(port, td.Port())

		c, err := NewClient(testCtx, &ClientConfig{
			URLs:        []string{fmt.Sprintf("ldap://127.0.0.1:%d", td.Port())},
			Certificate: td.Cert(),
		})
		require.NoError(err)
		err = c.connect(testCtx)
		defer c.Close(testCtx)
		require.NoError(err)

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN: TestDefaultUserDN,
			Filter: fmt.Sprintf("(uid=%s)", EscapeValue("alice*")),
		})
		require.NoError(err)
		require.Len(result.Entries, 1)
		assert.Equal("uid=alice,"+TestDefaultUserDN, result.Entries[0].DN)
		for _, e := range result.Entries {
			t.Log("***")
			t.Log(e.DN)
			for _, attr := range e.Attributes {
				t.Log(attr.Name, attr.Values)
			}
		}
		c.Close(testCtx)
	})
	t.Run("start-tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testFreePort(t)
		td := StartTestDirectory(
			t,
			WithTestPort(port),
			WithTestNoTLS(),
			WithTestDirectoryDefaults(&TestDirectoryDefaults{
				Users: testEntries,
			}),
		)
		assert.Equal(port, td.Port())

		c, err := NewClient(testCtx, &ClientConfig{
			URLs:        []string{fmt.Sprintf("ldap://127.0.0.1:%d", td.Port())},
			Certificate: td.Cert(),
		})
		require.NoError(err)
		err = c.connect(testCtx)
		defer c.Close(testCtx)
		require.NoError(err)
		caPool := x509.NewCertPool()
		require.True(caPool.AppendCertsFromPEM([]byte(td.Cert())))
		tlsConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "127.0.0.1",
		}
		c.StartTLS(tlsConfig)

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN: TestDefaultUserDN,
			Filter: fmt.Sprintf("(uid=%s)", EscapeValue("alice*")),
		})
		require.NoError(err)
		require.Len(result.Entries, 1)
		assert.Equal("uid=alice,"+TestDefaultUserDN, result.Entries[0].DN)
		for _, e := range result.Entries {
			t.Log("***")
			t.Log(e.DN)
			for _, attr := range e.Attributes {
				t.Log(attr.Name, attr.Values)
			}
		}
		c.Close(testCtx)
	})
	t.Run("with-mtls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		td := StartTestDirectory(
			t,
			WithTestMTLS(),
			WithTestDirectoryDefaults(&TestDirectoryDefaults{
				Users: testEntries,
			}),
		)

		c, err := NewClient(testCtx, &ClientConfig{
			URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificate: td.Cert(),
		})
		require.NoError(err)
		require.Error(c.connect(testCtx)) // should fail

		c, err = NewClient(testCtx, &ClientConfig{
			URLs:          []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificate:   td.Cert(),
			ClientTLSCert: td.ClientCert(),
			ClientTLSKey:  td.ClientKey(),
		})
		require.NoError(err)
		err = c.connect(testCtx)
		defer c.Close(testCtx)
		require.NoError(err)

		result, err := c.conn.Search(&ldap.SearchRequest{
			BaseDN: TestDefaultUserDN,
			Filter: fmt.Sprintf("(uid=%s)", EscapeValue("alice*")),
		})
		require.NoError(err)
		require.Len(result.Entries, 1)
		assert.Equal("uid=alice,"+TestDefaultUserDN, result.Entries[0].DN)
		for _, e := range result.Entries {
			t.Log("***")
			t.Log(e.DN)
			for _, attr := range e.Attributes {
				t.Log(attr.Name, attr.Values)
			}
		}
		c.Close(testCtx)
	})
}
