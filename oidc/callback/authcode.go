package callback

import (
	"context"
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

// AuthCode creates an oidc authorization code callback handler which
// uses a StateReader to read existing oidc.State(s) via the request's
// oidc "state" parameter as a key for the lookup.
//
// The SuccessResponseFunc is used to create a response when callback is
// successful. The ErrorResponseFunc is to create a response when the callback
// fails.
func AuthCode(ctx context.Context, p *oidc.AuthCodeProvider, rw StateReader, sFn SuccessResponseFunc, eFn ErrorResponseFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callbacks.AuthCodeState"

		reqState := req.FormValue("state")

		if rw == nil {
			responseErr := oidc.NewError(oidc.ErrNilParameter, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("state read/writer is nil"))
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

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")

		state, err := rw.Read(ctx, reqState)
		if err != nil {
			responseErr := oidc.NewError(oidc.ErrCodeUnknown, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to read auth code state"), oidc.WithWrap(err))
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if state == nil {
			// could have expired or it could be invalid... no way to known for sure
			responseErr := oidc.NewError(oidc.ErrNotFound, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("auth code state not found"))
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		if state.IsExpired() {
			responseErr := oidc.NewError(oidc.ErrExpiredState, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authentication state is expired"))
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		if reqState != state.Id() {
			// the stateReadWriter didn't return the correct state for the key
			// given... this is an internal sort of error on the part of the
			// reader, but given this error, we probably shouldn't update the state
			responseErr := oidc.NewError(oidc.ErrResponseStateInvalid, oidc.WithOp(op), oidc.WithKind(oidc.ErrIntegrityViolation), oidc.WithMsg("authen state and response state are not equal"))
			eFn(reqState, nil, responseErr, w, req)
			return
		}

		responseToken, err := p.Exchange(ctx, state, reqState, reqCode)
		if err != nil {
			responseErr := oidc.WrapError(err, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to exchange authorization code"))
			eFn(reqState, nil, responseErr, w, req)
			return
		}
		sFn(reqState, responseToken, w, req)
	}
}
