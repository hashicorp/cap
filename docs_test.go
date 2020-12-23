package cap_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func Example_oidc() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url"},
	)
	if err != nil {
		// handle error
	}

	// Create a provider
	p, err := oidc.NewProvider(pc)
	if err != nil {
		// handle error
	}
	defer p.Done()

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	state, err := oidc.NewState(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(context.Background(), state)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Create a http.Handler for OIDC authentication response redirects
	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		// Exchange a successful authentication's authorization code and
		// authorization state (received in a callback) for a verified Token.
		t, err := p.Exchange(context.Background(), state, "authorization-state", "authorization-code")
		if err != nil {
			// handle error
		}
		var claims map[string]interface{}
		if err := t.IDToken().Claims(&claims); err != nil {
			// handle error
		}

		// Get the user's claims via the provider's UserInfo endpoint
		var infoClaims map[string]interface{}
		err = p.UserInfo(context.Background(), t.StaticTokenSource(), claims["sub"].(string), &infoClaims)
		if err != nil {
			// handle error
		}
		resp := struct {
			IDTokenClaims  map[string]interface{}
			UserInfoClaims map[string]interface{}
		}{claims, infoClaims}
		enc := json.NewEncoder(w)
		if err := enc.Encode(resp); err != nil {
			// handle error
		}
	}
	http.HandleFunc("/callback", callbackHandler)
}