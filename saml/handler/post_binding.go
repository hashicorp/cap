package handler

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"text/template"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/hashicorp/cap/saml"
)

const (
	postBindingScriptSha256 = "T8Q9GZiIVtYoNIdF6UW5hDNgJudFDijQM/usO+xUkes="
)

//go:embed post_binding.gohtml
var PostBindingTempl string

// PostBindingHandlerFunc creates a handler function that handles a HTTP-POST binding SAML request.
func PostBindingHandlerFunc(sp *saml.ServiceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID, err := uuid.GenerateUUID()
		if err != nil {
			fmt.Println("failed to generate UUID", err)
			http.Error(w, "failed to generate UUID", http.StatusInternalServerError)
			return
		}

		authN, err := sp.CreateAuthNRequest(requestID)
		if err != nil {
			fmt.Println("failed to create authentication request", err)
			http.Error(w, "failed create authentication request", http.StatusBadRequest)
			return
		}

		payload, err := authN.CreateXMLDocument()
		if err != nil {
			fmt.Println("failed to create XML document from authentication request", err)
			http.Error(w, "failed to prepare authentication request", http.StatusInternalServerError)
			return
		}

		b64Payload := base64.StdEncoding.EncodeToString(payload)

		tmpl := template.Must(
			template.New("post-binding").Parse(PostBindingTempl),
		)

		writeRequestHeader(w)

		if err := tmpl.Execute(w, map[string]string{
			"Destination": authN.Destination,
			"SAMLRequest": b64Payload,
			"RelayState":  "abc123", // TODO: contains info where to redirect after successful auth.
		}); err != nil {
			fmt.Println("failed to execute POST binding template", err)
			http.Error(w, "failed to exectue POST binding temaplate", http.StatusInternalServerError)
			return
		}
	}
}

func writeRequestHeader(w http.ResponseWriter) {
	w.Header().Add("Content-Security-Policy", fmt.Sprintf("script-src '%s'", postBindingScriptSha256))
	w.Header().Add("Content-type", "text/html")
}
