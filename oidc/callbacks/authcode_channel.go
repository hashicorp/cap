package callbacks

import (
	"context"
	"net/http"

	"github.com/hashicorp/probo/oidc"
)

// LoginResp is written to the callback's done channel before returning
type LoginResp struct {
	Token oidc.Token // Token is populated when the callback successfully exchanges the auth code.
	Error error      // Error is populated when there's an error during the callback
}

// AuthCodeWithChannel creates an oidc authorization code callback handler which
// communicates it's results by writing a LoginResp to its done channel. This
// callback is a one-time use callback, since it takes a specific oidc.State as
// a parameter which represents only one oidc authentication attempt.  Because
// of it's one-time use case, it's most appropriate when implementing a solution
// that invokes a localhost http listener within the same process that kicked
// off the authorization code flow.  (see the vault jwt plugin as an example)
func AuthCodeWithChannel(ctx context.Context, p *oidc.AuthCodeProvider, state oidc.State, successResponseFunc SuccessResponseFunc, errorResponsefunc ErrorResponseFunc, doneCh chan<- LoginResp) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callbacks.AuthCodeChannel"
		var response string
		var responseToken *oidc.Token
		var responseErr error

		defer func() {
			_, _ = w.Write([]byte(response))
			doneCh <- LoginResp{*responseToken, responseErr}
		}()

		if state.IsExpired() {
			responseErr = oidc.NewError(oidc.ErrExpiredState, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authentication state is expired"))
			response = errorResponsefunc(nil, responseErr)
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
			response = errorResponsefunc(reqError, responseErr)
			return
		}

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")
		reqState := req.FormValue("state")

		if reqState != state.Id {
			responseErr = oidc.NewError(oidc.ErrResponseStateInvalid, oidc.WithOp(op), oidc.WithKind(oidc.ErrParameterViolation), oidc.WithMsg("authen state and response state are not equal"))
			response = errorResponsefunc(nil, responseErr)
			return
		}
		responseToken, err := p.Exchange(ctx, state, reqState, reqCode)
		if err != nil {
			responseErr = oidc.WrapError(err, oidc.WithOp(op), oidc.WithKind(oidc.ErrInternal), oidc.WithMsg("unable to exchange authorization code"))
			response = errorResponsefunc(nil, err)
			return
		}
		response = successResponseFunc(*responseToken)
	}
}
