// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

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
	pc, err := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback", "http://your_redirect_url/implicit-callback"},
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
	ttl := 2 * time.Minute
	authCodeAttempt, err := oidc.NewRequest(ttl, "http://your_redirect_url/auth-code-callback")
	if err != nil {
		// handle error
	}

	// Create a Request for a user's authentication attempt using an implicit
	// flow.
	implicitAttempt, err := oidc.NewRequest(ttl, "http://your_redirect_url/implicit-callback")
	if err != nil {
		// handle error
	}

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		state string,
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
		state string,
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
	authCodeCallback, err := AuthCode(context.Background(), p, &SingleRequestReader{Request: authCodeAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/auth-code-callback", authCodeCallback)

	// create an implicit flow callback and register it for use.
	implicitCallback, err := Implicit(context.Background(), p, &SingleRequestReader{Request: implicitAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/implicit-callback", implicitCallback)
}

func ExampleAuthCode() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback"},
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
	ttl := 2 * time.Minute
	authCodeAttempt, err := oidc.NewRequest(ttl, "http://your_redirect_url/auth-code-callback")
	if err != nil {
		// handle error
	}

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		state string,
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
		state string,
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
	authCodeCallback, err := AuthCode(context.Background(), p, &SingleRequestReader{Request: authCodeAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/auth-code-callback", authCodeCallback)
}

func ExampleImplicit() {
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/implicit-callback"},
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

	// Create a Request for a user's authentication attempt using an implicit
	// flow.
	ttl := 2 * time.Minute
	implicitAttempt, err := oidc.NewRequest(ttl, "http://your_redirect_url/implicit-callback")
	if err != nil {
		// handle error
	}

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		state string,
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
		state string,
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
	implicitCallback, err := Implicit(context.Background(), p, &SingleRequestReader{Request: implicitAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/implicit-callback", implicitCallback)
}
