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

func SuccessHandler(ctx context.Context, sc *stateCache) http.HandlerFunc {
	const op = "SuccessHandler"
	return func(w http.ResponseWriter, r *http.Request) {
		stateId := r.FormValue("state")
		s, err := sc.Read(ctx, stateId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading state during successful response: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer sc.Delete(stateId)
		extended, ok := s.(*extendedState)
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
	IdToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// printableToken is needed because the oidc.Token redacts the IdToken,
// AccessToken and RefreshToken
func printableToken(t oidc.Token) respToken {
	return respToken{
		IdToken:      string(t.IDToken()),
		AccessToken:  string(t.AccessToken()),
		RefreshToken: string(t.RefreshToken()),
		Expiry:       t.Expiry(),
	}
}
