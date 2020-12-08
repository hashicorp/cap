package callback

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/oidc"
	"golang.org/x/oauth2"
)

// Implicit creates an oidc implicit flow callback handler which
// uses a StateReader to read existing oidc.State(s) via the request's
// oidc "state" parameter as a key for the lookup.
//
// The SuccessResponseFunc is used to create a response when callback is
// successful. The ErrorResponseFunc is to create a response when the callback
// fails.
func Implicit(ctx context.Context, p *oidc.Provider, rw StateReader, sFn SuccessResponseFunc, eFn ErrorResponseFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callback.Implicit"

		reqState := req.FormValue("state")

		if rw == nil {
			responseErr := fmt.Errorf("%s: state read/writer is nil: %w", op, oidc.ErrNilParameter)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

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

		state, err := rw.Read(ctx, reqState)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to read auth code state: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if state == nil {
			// could have expired or it could be invalid... no way to known for
			// sure
			responseErr := fmt.Errorf("%s: auth code state not found: %w", op, oidc.ErrNotFound)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if state.IsExpired() {
			responseErr := fmt.Errorf("%s: authentication state is expired: %w", op, oidc.ErrExpiredState)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		if reqState != state.Id() {
			// the stateReadWriter didn't return the correct state for the key
			// given... this is an internal sort of error on the part of the
			// reader, but given this error, we probably shouldn't update the
			// state
			responseErr := fmt.Errorf("%s: authen state (%s) and response state (%s) are not equal: %w", op, state.Id(), reqState, oidc.ErrResponseStateInvalid)
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		var oath2Token *oauth2.Token
		reqAccessToken := req.FormValue("access_token")
		if reqAccessToken != "" {
			oath2Token = &oauth2.Token{
				AccessToken: reqAccessToken,
			}
		}

		reqIdToken := req.FormValue("id_token")
		responseToken, err := oidc.NewToken(oidc.IdToken(reqIdToken), oath2Token)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to create id_token: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if err := p.VerifyIDToken(ctx, responseToken.IdToken(), state.Nonce()); err != nil {
			responseErr := fmt.Errorf("%s: unable to verify id_token: %w", op, err)
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		sFn(reqState, responseToken, w, req)
	}
}
