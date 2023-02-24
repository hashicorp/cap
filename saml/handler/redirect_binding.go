package handler

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/models/core"
)

// TODO this doesn't work yet: Response cannot be decoded at the IDP.
// Re-visit how we deflate and b64 encode the request.
func RedirectBindingHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID, err := uuid.GenerateUUID()
		if err != nil {
			http.Error(w, "failed to generate UUID", http.StatusInternalServerError)
			return
		}

		authN, err := sp.CreateAuthNRequest(requestID)
		if err != nil {
			http.Error(w, "failed create authentication request", http.StatusBadRequest)
			return
		}

		payload, err := deflateAndB64Encode(authN)
		if err != nil {
			http.Error(w, "failed deflalte and encode authentication request", http.StatusInternalServerError)
			return
		}

		if len(payload) == 0 {
			http.Error(w, "authentication request is empty", http.StatusInternalServerError)
			return
		}

		redirect, err := url.Parse(authN.Destination)
		if err != nil {
			http.Error(w, "failed to parse destination URL", http.StatusBadRequest)
			return
		}

		vals := redirect.Query()
		vals.Set("SAMLRequest", url.QueryEscape(string(payload)))
		vals.Set("RelayState", url.QueryEscape("123abc"))
		redirect.RawQuery = vals.Encode()

		http.Redirect(w, r, redirect.String(), http.StatusFound)
	}
}

func deflateAndB64Encode(authn *core.AuthnRequest) ([]byte, error) {
	buf := bytes.Buffer{}

	b64w := base64.NewEncoder(base64.StdEncoding, &buf)

	fw, err := flate.NewWriter(b64w, 9)
	if err != nil {
		return nil, err
	}

	err = xml.NewEncoder(fw).Encode(authn)
	if err != nil {
		return nil, err
	}

	b64w.Close()
	fw.Close()

	return buf.Bytes(), nil
}
