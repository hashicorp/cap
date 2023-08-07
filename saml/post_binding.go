package saml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"text/template"

	"github.com/hashicorp/go-uuid"

	"github.com/hashicorp/cap/saml/models/core"
)

const (
	postBindingScriptSha256 = "T8Q9GZiIVtYoNIdF6UW5hDNgJudFDijQM/usO+xUkes="
)

func (sp *ServiceProvider) AuthnRequestPost(relayState string) ([]byte, *core.AuthnRequest, error) {
	// TODO change this
	requestID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, err
	}

	authN, err := sp.CreateAuthnRequest(requestID, core.ServiceBindingHTTPPost)
	if err != nil {
		return nil, nil, err
	}

	payload, err := authN.CreateXMLDocument()
	if err != nil {
		return nil, nil, err
	}

	b64Payload := base64.StdEncoding.EncodeToString(payload)

	tmpl := template.Must(
		template.New("post-binding").Parse(PostBindingTempl),
	)

	buf := bytes.Buffer{}

	if err := tmpl.Execute(&buf, map[string]string{
		"Destination": authN.Destination,
		"SAMLRequest": b64Payload,
		"RelayState":  relayState,
	}); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), authN, nil
}

func WritePostBindingRequestHeader(w http.ResponseWriter) {
	w.Header().Add("Content-Security-Policy", fmt.Sprintf("script-src '%s'", postBindingScriptSha256))
	w.Header().Add("Content-type", "text/html")
}
