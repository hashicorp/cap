// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func Example() {
	ctx := context.Background()
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

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow.  (See NewRequest(...) using the WithPKCE and
	// WithImplicit options for creating a Request that uses those flows.)
	oidcRequest, err := oidc.NewRequest(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(ctx, oidcRequest)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Create a http.Handler for OIDC authentication response redirects
	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		// Exchange a successful authentication's authorization code and
		// authorization state (received in a callback) for a verified Token.
		t, err := p.Exchange(ctx, oidcRequest, r.FormValue("state"), r.FormValue("code"))
		if err != nil {
			// handle error
		}
		var claims map[string]interface{}
		if err := t.IDToken().Claims(&claims); err != nil {
			// handle error
		}

		// Get the user's claims via the provider's UserInfo endpoint
		var infoClaims map[string]interface{}
		err = p.UserInfo(ctx, t.StaticTokenSource(), claims["sub"].(string), &infoClaims)
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
	// &{your_client_id [REDACTED: client secret] [openid] http://your_issuer/ [RS256] [http://your_redirect_url/callback] []  <nil> <nil> <nil>}
}

func ExampleWithProviderConfig() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"https://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"https://your_redirect_url/callback"},
		oidc.WithProviderConfig(&oidc.ProviderConfig{
			AuthURL:     "https://your_issuer/authorize",
			TokenURL:    "https://your_issuer/token",
			JWKSURL:     "https://your_issuer/.well-known/jwks.json",
			UserInfoURL: "https://your_issuer/userinfo",
		}),
	)
	if err != nil {
		// handle error
	}
	val, _ := json.Marshal(pc)
	fmt.Println(string(val))

	// Output:
	// {"ClientID":"your_client_id","ClientSecret":"[REDACTED: client secret]","Scopes":["openid"],"Issuer":"https://your_issuer/","SupportedSigningAlgs":["RS256"],"AllowedRedirectURLs":["https://your_redirect_url/callback"],"Audiences":null,"ProviderCA":"","RoundTripper":null,"ProviderConfig":{"AuthURL":"https://your_issuer/authorize","TokenURL":"https://your_issuer/token","UserInfoURL":"https://your_issuer/userinfo","JWKSURL":"https://your_issuer/.well-known/jwks.json"}}
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
	ctx := context.Background()
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

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow.  (See NewRequest(...) using the WithPKCE and
	// WithImplicit options for creating a Request that uses those flows.)
	oidcRequest, err := oidc.NewRequest(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(ctx, oidcRequest)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)
}

func ExampleProvider_Exchange() {
	ctx := context.Background()

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

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow.  (See NewRequest(...) using the WithPKCE and
	// WithImplicit options for creating a Request that uses those flows.)
	oidcRequest, err := oidc.NewRequest(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(ctx, oidcRequest)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Create a http.Handler for OIDC authentication response redirects
	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		// Exchange a successful authentication's authorization code and
		// authorization state (received in a callback) for a verified Token.
		t, err := p.Exchange(ctx, oidcRequest, r.FormValue("state"), r.FormValue("code"))
		if err != nil {
			// handle error
		}
		var claims map[string]interface{}
		if err := t.IDToken().Claims(&claims); err != nil {
			// handle error
		}

		// Get the user's claims via the provider's UserInfo endpoint
		var infoClaims map[string]interface{}
		err = p.UserInfo(ctx, t.StaticTokenSource(), claims["sub"].(string), &infoClaims)
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

func ExampleProvider_UserInfo() {
	ctx := context.Background()

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

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow.  (See NewRequest(...) using the WithPKCE and
	// WithImplicit options for creating a Request that uses those flows.)
	oidcRequest, err := oidc.NewRequest(2*time.Minute, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}

	// Create an auth URL
	authURL, err := p.AuthURL(ctx, oidcRequest)
	if err != nil {
		// handle error
	}
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Create a http.Handler for OIDC authentication response redirects
	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		// Exchange a successful authentication's authorization code and
		// authorization state (received in a callback) for a verified Token.
		t, err := p.Exchange(ctx, oidcRequest, r.FormValue("state"), r.FormValue("code"))
		if err != nil {
			// handle error
		}
		var claims map[string]interface{}
		if err := t.IDToken().Claims(&claims); err != nil {
			// handle error
		}

		// Get the user's claims via the provider's UserInfo endpoint
		var infoClaims map[string]interface{}
		err = p.UserInfo(ctx, t.StaticTokenSource(), claims["sub"].(string), &infoClaims)
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

func ExampleNewRequest() {
	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow.  (See NewRequest(...) using the WithPKCE and
	// WithImplicit options for creating a Request that uses those flows.)
	ttl := 2 * time.Minute
	oidcRequest, err := oidc.NewRequest(ttl, "http://your_redirect_url/callback")
	if err != nil {
		// handle error
	}
	fmt.Println(oidcRequest)

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow with PKCE
	v, err := oidc.NewCodeVerifier()
	if err != nil {
		// handle error
	}
	oidcRequest, err = oidc.NewRequest(ttl, "http://your_redirect_url/callback", oidc.WithPKCE(v))
	if err != nil {
		// handle error
	}
	fmt.Println(oidcRequest)

	// Create a Request for a user's authentication attempt that will use the
	// implicit flow.
	oidcRequest, err = oidc.NewRequest(ttl, "http://your_redirect_url/callback", oidc.WithImplicitFlow())
	if err != nil {
		// handle error
	}
	fmt.Println(oidcRequest)

	// Create a Request for a user's authentication attempt that will use the
	// authorization code flow and require a auth_time with a max_age of 0
	// seconds.
	ttl = 2 * time.Minute
	oidcRequest, err = oidc.NewRequest(ttl, "http://your_redirect_url/callback", oidc.WithMaxAge(0))
	if err != nil {
		// handle error
	}
	fmt.Println(oidcRequest)
}
