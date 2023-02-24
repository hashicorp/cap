package handler

import (
	"encoding/xml"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func MetadaHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meta := sp.CreateSPMetadata()
		xml.NewEncoder(w).Encode(meta)
	}
}
