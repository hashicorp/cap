package callbacks

import "github.com/hashicorp/probo/oidc"

// AuthenErrorResponse represents Oauth2 error responses.  See:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
type AuthenErrorResponse struct {
	Error       string
	Description string
	Uri         string
}

// SuccessResponseFunc is used by Callbacks to create an http response when the
// authorization code callback is successful
type SuccessResponseFunc func(oidc.Token) string

// ErrorResponseFunc is used by Callbacks to create an http response when the
// authorization code callback fails
type ErrorResponseFunc func(*AuthenErrorResponse, error) string
