package handler

import (
	"encoding/base64"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func ACSHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		samlResp := r.PostForm.Get("SAMLResponse")

		raw, err := base64.StdEncoding.DecodeString(samlResp)
		if err != nil {
			http.Error(w, "failed to decode saml response", http.StatusNotImplemented)
			return
		}

		w.Write(raw)
	}
}
