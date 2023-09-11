package handler

import (
	_ "embed"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// PostBindingHandlerFunc creates a handler function that handles a HTTP-POST binding SAML request.
func PostBindingHandlerFunc(sp *saml.ServiceProvider) (http.HandlerFunc, error) {
	const op = "handler.PostBindingHandlerFunc"
	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider", op)
	}
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

		err = saml.WritePostBindingRequestHeader(w)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf(
					"failed to write content headers: %s",
					err.Error(),
				),
				http.StatusInternalServerError,
			)
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
	}, nil
}
