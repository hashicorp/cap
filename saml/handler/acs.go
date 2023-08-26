package handler

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func ACSHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		samlResp := r.PostForm.Get("SAMLResponse")

		res, err := sp.ParseResponse(samlResp, "responseID", saml.InsecureSkipRequestIDValidation())
		if err != nil {
			fmt.Println("failed ot handle SAML response:", err.Error())
			http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Authenticated! %+v", res)
	}
}
