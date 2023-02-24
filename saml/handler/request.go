package handler

import (
	"net/http"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
)

func RequestHandler(sp *saml.ServiceProvider) http.HandlerFunc {
	switch sp.ServiceBinding() {
	case core.ServiceBindingHTTPPost:
		return PostBindingHandlerFunc(sp)
	case core.ServiceBindingHTTPRedirect:
		return RedirectBindingHandlerFunc(sp)
	default:
		return PostBindingHandlerFunc(sp)
	}
}
