package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
)

func CallbackHandler(ctx context.Context, p *oidc.Provider, sc *stateCache, withImplicit bool) http.HandlerFunc {
	if withImplicit {
		return callback.Implicit(ctx, p, sc, successFn(ctx, sc), failedFn(ctx, sc))
	}
	return callback.AuthCode(ctx, p, sc, successFn(ctx, sc), failedFn(ctx, sc))
}

func successFn(ctx context.Context, sc *stateCache) callback.SuccessResponseFunc {
	return func(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		s, err := sc.Read(ctx, stateID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := sc.SetToken(s.ID(), t); err != nil {
			fmt.Fprintf(os.Stderr, "error updating state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect to logged in page
		http.Redirect(w, req, fmt.Sprintf("/success?state=%s", stateID), http.StatusSeeOther)
	}
}

func failedFn(ctx context.Context, sc *stateCache) callback.ErrorResponseFunc {
	const op = "failedFn"
	return func(stateID string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
		var responseErr error
		defer func() {
			if _, err := w.Write([]byte(responseErr.Error())); err != nil {
				fmt.Fprintf(os.Stderr, "error writing failed response: %s\n", err)
			}
		}()

		if e != nil {
			fmt.Fprintf(os.Stderr, "callback error: %s\n", e.Error())
			responseErr = e
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r != nil {
			fmt.Fprintf(os.Stderr, "callback error from oidc provider: %s\n", r)
			responseErr = fmt.Errorf("%s: callback error from oidc provider: %s", op, r)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		responseErr = errors.New("Unknown error from callback")
	}
}
