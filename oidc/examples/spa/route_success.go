package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func SuccessHandler(ctx context.Context, rc *requestCache) http.HandlerFunc {
	const op = "SuccessHandler"
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")
		oidcRequest, err := rc.Read(ctx, state)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading state during successful response: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rc.Delete(state)
		extended, ok := oidcRequest.(extendedRequest)
		if !ok {
			err := fmt.Errorf("%s: not an extended state", op)
			fmt.Fprint(os.Stderr, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		t := printableToken(extended.t)
		tokenData, err := json.MarshalIndent(t, "", "    ")
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(tokenData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type respToken struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// printableToken is needed because the oidc.Token redacts the IDToken,
// AccessToken and RefreshToken
func printableToken(t oidc.Token) respToken {
	return respToken{
		IDToken:      string(t.IDToken()),
		AccessToken:  string(t.AccessToken()),
		RefreshToken: string(t.RefreshToken()),
		Expiry:       t.Expiry(),
	}
}
