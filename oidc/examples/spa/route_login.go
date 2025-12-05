// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func LoginHandler(ctx context.Context, p *oidc.Provider, rc *requestCache, timeout time.Duration, redirectURL string, requestOptions []oidc.Option) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oidcRequest, err := oidc.NewRequest(timeout, redirectURL, requestOptions...)
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			return
		}
		rc.Add(oidcRequest)

		authURL, err := p.AuthURL(ctx, oidcRequest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
			return
		}
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}
