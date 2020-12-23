package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func Example() {
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
		fmt.Println("id_token claims: ", claims)
		fmt.Println("UserInfo claims: ", infoClaims)
	}
	http.HandleFunc("/callback", callbackHandler)
}

func ExampleNewConfig() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/callback"},
	)
	if err != nil {
		// handle error
	}
	fmt.Println(pc)

	// Output:
	// &{your_client_id [REDACTED: client secret] [openid] http://your_issuer/ [RS256] [http://your_redirect_url/callback] []  <nil>}
}

func ExampleNewProvider() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/callback"},
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
}

func ExampleProvider_AuthURL() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/callback"},
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
	s, err := oidc.NewState(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(context.Background(), s)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)
}

func ExampleProvider_Exchange() {
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
		fmt.Println("id_token claims: ", claims)
		fmt.Println("UserInfo claims: ", infoClaims)
	}
	http.HandleFunc("/callback", callbackHandler)
}

func ExampleProvider_UserInfo() {
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
		fmt.Println("id_token claims: ", claims)
		fmt.Println("UserInfo claims: ", infoClaims)
	}
	http.HandleFunc("/callback", callbackHandler)
}

func ExampleNewState() {
	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	ttl := 2 * time.Minute
	s, err := oidc.NewState(ttl, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}
	fmt.Println(s)

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow with PKCE
	v, err := oidc.NewCodeVerifier()
	if err != nil {
		// handle error
	}
	s, err = oidc.NewState(ttl, "http://your_redirect_url/callback", oidc.WithPKCE(v))
	if err != nil {
		// handle error
	}
	fmt.Println(s)

	// Create a State for a user's authentication attempt that will use the
	// implicit flow.
	s, err = oidc.NewState(ttl, "http://your_redirect_url/callback", oidc.WithImplicitFlow())
	if err != nil {
		// handle error
	}
	fmt.Println(s)

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow and require a auth_time with a max_age of 0
	// seconds.
	ttl = 2 * time.Minute
	s, err = oidc.NewState(ttl, "http://your_redirect_url/callback", oidc.WithMaxAge(0))
	if err != nil {
		// handle error
	}
	fmt.Println(s)
}
