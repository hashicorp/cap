package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
)

func Example() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL
	authURL, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Exchange a successful authentication's authorization code and
	// authorization state (received in a callback) for a verified Token.
	t, _ := p.Exchange(context.Background(), s, "authorization-state", "authorization-code")
	fmt.Printf("id_token: %v\n", string(t.IDToken()))

	// Create an authorization code flow callback
	successFn := func(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	errorFn := func(stateID string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	callback := callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
	http.HandleFunc("/callback", callback)

	// Get the user's claims via the provider's UserInfo endpoint
	var infoClaims map[string]interface{}
	_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
	fmt.Println("UserInfo claims: ", infoClaims)

}

func ExampleNewConfig() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)
	fmt.Println(pc)

	// Output:
	// &{your_client_id [REDACTED: client secret] [openid] http://your_issuer/ [RS256] http://your_redirect_url [http://your_redirect_url] []  <nil>}
}

func ExampleNewProvider() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()
}

func ExampleProvider_AuthURL() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL
	authURL, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authURL)
}

func ExampleProvider_Exchange() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL
	authURL, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Exchange an authorizationCode and authorizationState received via a
	// callback from successful oidc authentication response for a verified
	// Token.
	t, _ := p.Exchange(context.Background(), s, "RECEIVED_STATE", "RECEIVED_CODE")
	fmt.Printf("id_token: %v\n", string(t.IDToken()))
}

func ExampleProvider_UserInfo() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your_issuer/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		"http://your_redirect_url",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Exchange a successful authentication's authorization code and
	// authorization state (received in a callback) for a verified Token.
	t, _ := p.Exchange(context.Background(), s, "authorization-state", "authorization-code")

	// Get the UserInfo claims
	var infoClaims map[string]interface{}
	_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
	fmt.Println("UserInfo claims: ", infoClaims)
}
