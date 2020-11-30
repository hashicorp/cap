package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func LoginHandler(ctx context.Context, p *oidc.AuthCodeProvider, sc *stateCache, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := oidc.NewState(timeout)
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			return
		}
		sc.Add(s)

		authUrl, err := p.AuthURL(context.Background(), s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
			return
		}
		http.Redirect(w, r, authUrl, http.StatusTemporaryRedirect)
	}
}
