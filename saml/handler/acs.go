package handler

import (
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func ACSHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SAML Response received, but ACS is not implemented", http.StatusNotImplemented)
	}
}
