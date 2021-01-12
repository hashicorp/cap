package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
)

func CallbackHandler(ctx context.Context, p *oidc.Provider, rc *requestCache, withImplicit bool) (http.HandlerFunc, error) {
	if withImplicit {
		c, err := callback.Implicit(ctx, p, rc, successFn(ctx, rc), failedFn(ctx, rc))
		if err != nil {
			return nil, fmt.Errorf("CallbackHandler: %w", err)
		}
		return c, nil
	}
	c, err := callback.AuthCode(ctx, p, rc, successFn(ctx, rc), failedFn(ctx, rc))
	if err != nil {
		return nil, fmt.Errorf("CallbackHandler: %w", err)
	}
	return c, nil
}

func successFn(ctx context.Context, rc *requestCache) callback.SuccessResponseFunc {
	return func(state string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		oidcRequest, err := rc.Read(ctx, state)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := rc.SetToken(oidcRequest.State(), t); err != nil {
			fmt.Fprintf(os.Stderr, "error updating state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect to logged in page
		http.Redirect(w, req, fmt.Sprintf("/success?state=%s", state), http.StatusSeeOther)
	}
}

func failedFn(ctx context.Context, rc *requestCache) callback.ErrorResponseFunc {
	const op = "failedFn"
	return func(state string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
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
		responseErr = fmt.Errorf("%s: unknown error from callback", op)
	}
}
