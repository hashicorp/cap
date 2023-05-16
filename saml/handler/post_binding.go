package handler

import (
	_ "embed"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// PostBindingHandlerFunc creates a handler function that handles a HTTP-POST binding SAML request.
func PostBindingHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		templ, _, err := sp.AuthNRequestPost("")
		if err != nil {
			http.Error(w, "Failed to do SAML POST authentication request", http.StatusInternalServerError)
			return
		}

		_, err = w.Write(templ)
		if err != nil {
			http.Error(w, "failed to serve post binding request", http.StatusInternalServerError)
			return
		}
	}
}
