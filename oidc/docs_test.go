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
		"http://YOUR_ISSUER/",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"http://YOUR_REDIRECT_URL",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL from the provider using the user's auth attempt state
	authUrl, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authUrl)

	// Exchange an authorizationCode and authorizationState received via a
	// callback from successful oidc authentication response for a verified
	// Token.
	t, _ := p.Exchange(context.Background(), s, "RECEIVED_STATE", "RECEIVED_CODE")
	fmt.Printf("id_token: %v\n", string(t.IDToken()))

	// Create an auth code callback
	successFn := func(stateId string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	errorFn := func(stateId string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	callback := callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
	http.HandleFunc("/callback", callback)

	// Get the user's claims via the UserInfo endpoint
	var infoClaims map[string]interface{}
	_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
	fmt.Println("UserInfo claims: ", infoClaims)

}

func ExampleNewConfig() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://YOUR_ISSUER/",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"http://YOUR_REDIRECT_URL",
	)
	fmt.Println(pc)

	// Output:
	// &{YOUR_CLIENT_ID [REDACTED: client secret] [openid] http://YOUR_ISSUER/ [RS256] http://YOUR_REDIRECT_URL []  <nil>}
}

func ExampleNewProvider() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://YOUR_ISSUER/",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"http://YOUR_REDIRECT_URL",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()
}

func ExampleProvider_AuthURL() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"YOUR_ISSUER",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"YOUR_REDIRECT_URL",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL from the provider using the user's auth attempt state
	authUrl, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authUrl)
}

func ExampleProvider_Exchange() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://YOUR_ISSUER/",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"http://YOUR_REDIRECT_URL",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Create an auth URL from the provider using the user's auth attempt state
	authUrl, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authUrl)

	// Exchange an authorizationCode and authorizationState received via a
	// callback from successful oidc authentication response for a verified
	// Token.
	t, _ := p.Exchange(context.Background(), s, "RECEIVED_STATE", "RECEIVED_CODE")
	fmt.Printf("id_token: %v\n", string(t.IDToken()))
}

func ExampleProvider_UserInfo() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://YOUR_ISSUER/",
		"YOUR_CLIENT_ID",
		"YOUR_CLIENT_SECRET",
		[]oidc.Alg{oidc.RS256},
		"http://YOUR_REDIRECT_URL",
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt
	ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl)

	// Exchange an authorizationCode and authorizationState received via a
	// callback from successful oidc authentication response for a verified
	// Token.
	t, _ := p.Exchange(context.Background(), s, "RECEIVED_STATE", "RECEIVED_CODE")

	var infoClaims map[string]interface{}
	_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
	fmt.Println("UserInfo claims: ", infoClaims)
}
