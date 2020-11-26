package callbacks

import (
	"context"
	"net/http"

	"github.com/hashicorp/probo/oidc"
)

// AuthCodeState defines a state which is used by the AuthCodeWithState to
// communicate the callbacks results
type AuthCodeState struct {
	Oidc          oidc.State // Oidc is the auth code flow's oidc state.  The State.Id is the key for the entry
	ResponseToken oidc.Token // ResponseToken is the oidc.Token that's the result of a successful authorization code exchange
}

// StateReader defines an interface for finding and reading an AuthCodeState.
// Implementions must be concurrently safe, since the reader will likley be used
// within a concurrent http.Handler
type StateReader interface {
	// Read an existing AuthCodeState entry.  The returned AuthCodeState.Oidc.Id
	// must match the oidcStateId used to look it up. Implementions must be
	// concurrently safe, which likely means returning a deep copy as the
	// *AuthCodeState
	Read(ctx context.Context, oidcStateId string) (*AuthCodeState, error)
}

// AuthCodeWithState creates an oidc authorization code callback handler which
// uses a StateReader to read existing AuthCodeStates via the request's
// oidc "state" parameter as a key for the lookup.
//
// The SuccessResponseFunc is used to create a response when callback is
// successful. The ErrorResponseFunc is to create a response when the callback
// fails.
func AuthCodeWithState(ctx context.Context, p *oidc.AuthCodeProvider, rw StateReader, sFn SuccessResponseFunc, eFn ErrorResponseFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callbacks.AuthCodeState"
		var response []byte
		var responseToken oidc.Token
		var state *AuthCodeState

		defer func() {
			_, _ = w.Write(response)

		}()
		reqState := req.FormValue("state")

		if rw == nil {
			responseErr := oidc.NewError(oidc.ErrNilParameter, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("state read/writer is nil"))
			response = eFn(reqState, nil, responseErr)
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
			response = eFn(reqState, reqError, nil)
			return
		}

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")

		state, err := rw.Read(ctx, reqState)
		if err != nil {
			responseErr := oidc.NewError(oidc.ErrCodeUnknown, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to read auth code state"), oidc.WithWrap(err))
			response = eFn(reqState, nil, responseErr)
			return
		}
		if state == nil {
			// could have expired or it could be invalid... no way to known for sure
			responseErr := oidc.NewError(oidc.ErrNotFound, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("auth code state not found"))
			response = eFn(reqState, nil, responseErr)
			return
		}
		if state.Oidc.IsExpired() {
			responseErr := oidc.NewError(oidc.ErrExpiredState, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authentication state is expired"))
			response = eFn(reqState, nil, responseErr)
			return
		}

		if reqState != state.Oidc.Id {
			// the stateReadWriter didn't return the correct state for the key
			// giving... this is an internal sort of error on the part of the
			// reader, but given this error, we probably shouldn't update the state
			responseErr := oidc.NewError(oidc.ErrResponseStateInvalid, oidc.WithOp(op), oidc.WithKind(oidc.ErrIntegrityViolation), oidc.WithMsg("authen state and response state are not equal"))
			response = eFn(reqState, nil, responseErr)
			return
		}

		responseToken, err = p.Exchange(ctx, state.Oidc, reqState, reqCode)
		if err != nil {
			responseErr := oidc.WrapError(err, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to exchange authorization code"))
			response = eFn(reqState, nil, responseErr)
			return
		}
		response = sFn(reqState, responseToken)
	}
}
