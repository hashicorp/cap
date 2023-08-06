package handler

import (
	"encoding/xml"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

func MetadaHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		meta := sp.CreateMetadata()
		err := xml.NewEncoder(w).Encode(meta)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
