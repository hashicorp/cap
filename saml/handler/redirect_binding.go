package handler

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func RedirectBindingHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL, _, err := sp.AuthnRequestRedirect("relayState")
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("failed to create SAML Authn Request: %s", err.Error()),
				http.StatusInternalServerError,
			)
			return
		}

		redirect := redirectURL.String()

		fmt.Printf("Redirect URL: %s\n", redirect)

		http.Redirect(w, r, redirect, http.StatusFound)
	}
}
