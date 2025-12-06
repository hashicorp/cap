// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package handler

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// ACSHandlerFunc creates a handler function that handles a SAML
// ACS request
func ACSHandlerFunc(sp *saml.ServiceProvider) (http.HandlerFunc, error) {
	const op = "handler.ACSHandler"
	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider", op)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		samlResp := r.PostForm.Get("SAMLResponse")

		res, err := sp.ParseResponse(samlResp, "responseID", saml.InsecureSkipRequestIDValidation())
		if err != nil {
			fmt.Println("failed to handle SAML response:", err.Error())
			http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Authenticated! %+v", res)
	}, nil
}
