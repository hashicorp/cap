package callbacks

import (
	"context"
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

// LoginResp is used by AuthCodeWithChannel.  The callback writes its response
// to the returned <-chan LoginResp.
type LoginResp struct {
	Token oidc.Token // Token is populated when the callback successfully exchanges the auth code.
	Error error      // Error is populated when there's an error during the callback
}

// AuthCodeWithChannel creates an oidc authorization code callback handler which
// communicates results by writing a LoginResp to a cannel. This callback is a
// one-time use callback, since it takes a specific oidc.State as a parameter
// which represents only one oidc authentication attempt.  Because of it's
// one-time use case, it's most appropriate when implementing a solution that
// invokes a localhost http listener within the same process that kicked
// off the authorization code flow.  (see the vault jwt plugin as an example)
//
// The SuccessResponseFunc is used to create a response when callback is
// successful. The ErrorResponseFunc is to create a response when the callback
// fails.
func AuthCodeWithChannel(ctx context.Context, p *oidc.AuthCodeProvider, state oidc.State, sFn SuccessResponseFunc, eFn ErrorResponseFunc) (<-chan LoginResp, http.HandlerFunc) {
	doneCh := make(chan LoginResp)
	return doneCh, func(w http.ResponseWriter, req *http.Request) {
		const op = "callbacks.AuthCodeChannel"
		var response []byte
		var responseToken oidc.Token
		var responseErr error

		defer func() {
			_, _ = w.Write(response)
			doneCh <- LoginResp{responseToken, responseErr}
			close(doneCh)
		}()

		reqState := req.FormValue("state")
		if state.IsExpired() {
			responseErr = oidc.NewError(oidc.ErrExpiredState, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authentication state is expired"))
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
			responseErr = oidc.NewError(oidc.ErrLoginFailed, oidc.WithOp(op), oidc.WithKind(oidc.ErrLoginViolation), oidc.WithMsg("User failed to complete authentication/authorization"))
			response = eFn(reqState, reqError, responseErr)
			return
		}

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")

		if reqState != state.Id() {
			responseErr = oidc.NewError(oidc.ErrResponseStateInvalid, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authen state and response state are not equal"))
			response = eFn(reqState, nil, responseErr)
			return
		}
		responseToken, err := p.Exchange(ctx, state, reqState, reqCode)
		if err != nil {
			responseErr = oidc.WrapError(err, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to exchange authorization code"))
			response = eFn(reqState, nil, err)
			return
		}
		response = sFn(reqState, responseToken)
	}
}
