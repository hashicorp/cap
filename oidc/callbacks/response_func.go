package callbacks

import "github.com/hashicorp/probo/oidc"

// AuthenErrorResponse represents Oauth2 error responses.  See:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
type AuthenErrorResponse struct {
	Error       string
	Description string
	Uri         string
}

// SuccessResponseFunc is used by Callbacks to create a response when the
// authorization code callback is successful.
//
// The function stateId parameter will contain the state that was returned as
// part of a successful oidc  authentication response. The function must return
// a []byte containing whatever context (html, JSON, etc) it would like to
// consume with it's own http.Handler wrapper or whatever content it simply
// wishes to send back to the user.
//
// Just a reminder that the function parameters could also be used to
// update the oidc.State for the request or log info about the request, if the
// implementation requires it.
type SuccessResponseFunc func(stateId string, t oidc.Token) []byte

// ErrorResponseFunc is used by Callbacks to create a response when the
// authorization code callback fails.
//
// The function receives the stateId returned as part of the oidc authentication
// response.  It also gets parameters for the oidc authentication error response
// and/or the callback error raised while processing the request.  The function
// must return a []byte containing whatever context (html, JSON, etc) it would
// like to consume with it's own http.Handler wrapper or whatever content it
// simply wishes to send back to the user.
//
// Just a reminder that the function parameters could also be used to
// update the oidc.State for the request or log info about the request, if the
// implementation requires it.
type ErrorResponseFunc func(stateId string, r *AuthenErrorResponse, e error) []byte
