package callback

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func Example() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback", "http://your_redirect_url/implicit-callback"},
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	ttl := 2 * time.Minute
	authCodeAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/auth-code-callback")

	// Create a State for a user's authentication attempt using an implicit
	// flow.
	implicitAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/implicit-callback")

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		stateID string,
		t oidc.Token,
		w http.ResponseWriter,
		req *http.Request,
	) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	// A function to handle errors and failed attempts.
	errorFn := func(
		stateID string,
		r *AuthenErrorResponse,
		e error,
		w http.ResponseWriter,
		req *http.Request,
	) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	// create the authorization code callback and register it for use.
	authCodeCallback, _ := AuthCode(context.Background(), p, &SingleStateReader{State: authCodeAttempt}, successFn, errorFn)
	http.HandleFunc("/auth-code-callback", authCodeCallback)

	// create an implicit flow callback and register it for use.
	implicitCallback, _ := Implicit(context.Background(), p, &SingleStateReader{State: implicitAttempt}, successFn, errorFn)
	http.HandleFunc("/implicit-callback", implicitCallback)
}

func ExampleAuthCode() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback"},
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	ttl := 2 * time.Minute
	authCodeAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/auth-code-callback")

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		stateID string,
		t oidc.Token,
		w http.ResponseWriter,
		req *http.Request,
	) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	// A function to handle errors and failed attempts.
	errorFn := func(
		stateID string,
		r *AuthenErrorResponse,
		e error,
		w http.ResponseWriter,
		req *http.Request,
	) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	// create the authorization code callback and register it for use.
	authCodeCallback, _ := AuthCode(context.Background(), p, &SingleStateReader{State: authCodeAttempt}, successFn, errorFn)
	http.HandleFunc("/auth-code-callback", authCodeCallback)
}

func ExampleImplicit() {
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/implicit-callback"},
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt using an implicit
	// flow.
	ttl := 2 * time.Minute
	implicitAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/implicit-callback")

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		stateID string,
		t oidc.Token,
		w http.ResponseWriter,
		req *http.Request,
	) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	// A function to handle errors and failed attempts.
	errorFn := func(
		stateID string,
		r *AuthenErrorResponse,
		e error,
		w http.ResponseWriter,
		req *http.Request,
	) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}

	// create an implicit flow callback and register it for use.
	implicitCallback, _ := Implicit(context.Background(), p, &SingleStateReader{State: implicitAttempt}, successFn, errorFn)
	http.HandleFunc("/implicit-callback", implicitCallback)
}
