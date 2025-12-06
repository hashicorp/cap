// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/oidc"
	"golang.org/x/oauth2"
)

// Implicit creates an oidc implicit flow callback handler which
// uses a RequestReader to read existing oidc.Request(s) via the request's
// oidc "state" parameter as a key for the lookup.
//
// It should be noted that if your OIDC provider supports PKCE, then
// use it over the implicit flow
//
// The SuccessResponseFunc is used to create a response when callback is
// successful.
//
// The ErrorResponseFunc is to create a response when the callback fails.
func Implicit(ctx context.Context, p *oidc.Provider, rw RequestReader, sFn SuccessResponseFunc, eFn ErrorResponseFunc) (http.HandlerFunc, error) {
	const op = "callback.Implicit"
	if p == nil {
		return nil, fmt.Errorf("%s: provider is empty: %w", op, oidc.ErrInvalidParameter)
	}
	if rw == nil {
		return nil, fmt.Errorf("%s: request reader is empty: %w", op, oidc.ErrInvalidParameter)
	}
	if sFn == nil {
		return nil, fmt.Errorf("%s: success response func is empty: %w", op, oidc.ErrInvalidParameter)
	}
	if eFn == nil {
		return nil, fmt.Errorf("%s: error response func is empty: %w", op, oidc.ErrInvalidParameter)
	}
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callback.Implicit"

		reqState := req.FormValue("state")

		if err := req.FormValue("error"); err != "" {
			// get parameters from either the body or query parameters.
			// FormValue prioritizes body values, if found
			reqError := &AuthenErrorResponse{
				Error:       err,
				Description: req.FormValue("error_description"),
				Uri:         req.FormValue("error_uri"),
			}
			eFn(reqState, reqError, nil, w, req)
			return
		}
		if reqState == "" {
			responseErr := fmt.Errorf("%s: empty state parameter: %w", op, oidc.ErrInvalidParameter)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		oidcRequest, err := rw.Read(ctx, reqState)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to read auth code request: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if oidcRequest == nil {
			// could have expired or it could be invalid... no way to known for
			// sure
			responseErr := fmt.Errorf("%s: auth code request not found: %w", op, oidc.ErrNotFound)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		useImplicit, includeAccessToken := oidcRequest.ImplicitFlow()
		if !useImplicit {
			responseErr := fmt.Errorf("%s: request (%s) should not be using the implicit flow: %w", op, oidcRequest.State(), oidc.ErrInvalidFlow)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		if oidcRequest.IsExpired() {
			responseErr := fmt.Errorf("%s: authentication request is expired: %w", op, oidc.ErrExpiredRequest)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		if reqState != oidcRequest.State() {
			// the stateReadWriter didn't return the correct state for the key
			// given... this is an internal sort of error on the part of the
			// reader.
			responseErr := fmt.Errorf("%s: authen state (%s) and response state (%s) are not equal: %w", op, oidcRequest.State(), reqState, oidc.ErrInvalidResponseState)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		reqIDToken := oidc.IDToken(req.FormValue("id_token"))
		if _, err := p.VerifyIDToken(ctx, reqIDToken, oidcRequest); err != nil {
			responseErr := fmt.Errorf("%s: unable to verify id_token: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		var oath2Token *oauth2.Token
		if includeAccessToken {
			reqAccessToken := req.FormValue("access_token")
			if reqAccessToken != "" {
				if _, err := reqIDToken.VerifyAccessToken(oidc.AccessToken(reqAccessToken)); err != nil {
					responseErr := fmt.Errorf("%s: unable to verify access_token: %w", op, err)
					eFn(reqState, nil, responseErr, w, req)
					return
				}
				oath2Token = &oauth2.Token{
					AccessToken: reqAccessToken,
				}
			}
		}

		responseToken, err := oidc.NewToken(oidc.IDToken(reqIDToken), oath2Token)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to create response tokens: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		sFn(reqState, responseToken, w, req)
	}, nil
}
