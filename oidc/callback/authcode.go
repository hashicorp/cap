// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

// AuthCode creates an oidc authorization code callback handler which
// uses a RequestReader to read existing oidc.Request(s) via the request's
// oidc "state" parameter as a key for the lookup.  In additional to the
// typical authorization code flow, it also handles the authorization code flow
// with PKCE.
//
// The SuccessResponseFunc is used to create a response when callback is
// successful.
//
// The ErrorResponseFunc is to create a response when the callback fails.
func AuthCode(ctx context.Context, p *oidc.Provider, rw RequestReader, sFn SuccessResponseFunc, eFn ErrorResponseFunc) (http.HandlerFunc, error) {
	const op = "callback.AuthCode"
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
		const op = "callback.AuthCode"

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

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")

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
		if oidcRequest.IsExpired() {
			responseErr := fmt.Errorf("%s: authentication request is expired: %w", op, oidc.ErrExpiredRequest)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		if reqState != oidcRequest.State() {
			// the stateReadWriter didn't return the correct state for the key
			// given... this is an internal sort of error on the part of the
			// reader.
			responseErr := fmt.Errorf("%s: authentication state and response state are not equal: %w", op, oidc.ErrInvalidResponseState)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if useImplicit, _ := oidcRequest.ImplicitFlow(); useImplicit {
			responseErr := fmt.Errorf("%s: state (%s) should not be using the authorization code flow: %w", op, oidcRequest.State(), oidc.ErrInvalidFlow)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		responseToken, err := p.Exchange(ctx, oidcRequest, reqState, reqCode)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to exchange authorization code: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		sFn(reqState, responseToken, w, req)
	}, nil
}
