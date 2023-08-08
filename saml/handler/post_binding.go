package handler

import (
	_ "embed"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// PostBindingHandlerFunc creates a handler function that handles a HTTP-POST binding SAML request.
func PostBindingHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		templ, _, err := sp.AuthnRequestPost("")
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to do SAML POST authentication request: %s", err.Error()),
				http.StatusInternalServerError,
			)
			return
		}

		_, err = w.Write(templ)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf(
					"failed to serve post binding request: %s",
					err.Error(),
				),
				http.StatusInternalServerError,
			)
			return
		}
	}
}
