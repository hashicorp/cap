// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// MetadataHandlerFunc creates a handler function that handles a SAML
// metadata request
func MetadataHandlerFunc(sp *saml.ServiceProvider) (http.HandlerFunc, error) {
	const op = "handler.MetadataHandlerFunc"
	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider", op)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		meta := sp.CreateMetadata()
		err := xml.NewEncoder(w).Encode(meta)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}, nil
}
