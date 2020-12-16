package callback

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/require"
)

// testSuccessFn is a test SuccessResponseFunc
func testSuccessFn(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("login successful"))
}

// testFailFn is a test ErrorResponseFunc
func testFailFn(stateID string, r *AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		j, _ := json.Marshal(&AuthenErrorResponse{
			Error:       "internal-callback-error",
			Description: e.Error(),
		})
		_, _ = w.Write(j)
		return
	}
	if r != nil {
		w.WriteHeader(http.StatusUnauthorized)
		j, _ := json.Marshal(r)
		_, _ = w.Write(j)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	j, _ := json.Marshal(&AuthenErrorResponse{
		Error: "unknown-callback-error",
	})
	_, _ = w.Write(j)
}

// testNewProvider creates a new Provider.  It uses the TestProvider (tp) to properly
// construct the provider's configuration (see testNewConfig). This is helpful internally, but
// intentionally not exported.
func testNewProvider(t *testing.T, clientID, clientSecret, redirectURL string, tp *oidc.TestProvider) *oidc.Provider {
	const op = "testNewProvider"
	t.Helper()
	require := require.New(t)
	require.NotEmptyf(clientID, "%s: client id is empty", op)
	require.NotEmptyf(clientSecret, "%s: client secret is empty", op)
	require.NotEmptyf(redirectURL, "%s: redirect URL is empty", op)

	tc := testNewConfig(t, clientID, clientSecret, redirectURL, tp)
	p, err := oidc.NewProvider(tc)
	require.NoError(err)
	t.Cleanup(p.Done)
	return p
}

// testNewConfig creates a new config from the TestProvider. It will set the
// TestProvider's client ID/secret and use the TestProviders signing algorithm
// when building the configuration. This is helpful internally, but
// intentionally not exported.
func testNewConfig(t *testing.T, clientID, clientSecret, allowedRedirectURL string, tp *oidc.TestProvider) *oidc.Config {
	const op = "testNewConfig"
	t.Helper()
	require := require.New(t)

	require.NotEmptyf(clientID, "%s: client id is empty", op)
	require.NotEmptyf(clientSecret, "%s: client secret is empty", op)
	require.NotEmptyf(allowedRedirectURL, "%s: redirect URL is empty", op)

	tp.SetClientCreds(clientID, clientSecret)
	_, _, alg := tp.SigningKeys()
	c, err := oidc.NewConfig(
		tp.Addr(),
		clientID,
		oidc.ClientSecret(clientSecret),
		[]oidc.Alg{alg},
		[]string{allowedRedirectURL},
		nil,
		oidc.WithProviderCA(tp.CACert()),
	)
	require.NoError(err)
	return c
}
