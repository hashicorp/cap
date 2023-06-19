package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/handler"
)

func main() {
	envs := map[string]string{
		"certFile": os.Getenv("SAML_CERT_FILE"),
		"keyFile":  os.Getenv("SAML_KEY_FILE"),
	}

	entityID, err := url.Parse("http://saml.julz/example")
	exitOnError(err)

	acs, err := url.Parse("http://localhost:8000/saml/acs")
	exitOnError(err)

	issuer, err := url.Parse("https://samltest.id")
	exitOnError(err)

	metadataURL, err := url.Parse("https://samltest.id/saml/idp")
	exitOnError(err)

	cfg := saml.NewConfig(entityID, acs, issuer, metadataURL)

	if envs["certFile"] != "" && envs["keyFile"] != "" {
		cert, err := tls.LoadX509KeyPair(envs["certFile"], envs["keyFile"])
		exitOnError(err)

		cfg.Certificate = &cert
	}

	sp, err := saml.NewServiceProvider(cfg)
	exitOnError(err)

	http.HandleFunc("/saml/acs", handler.ACSHandlerFunc(sp))
	http.HandleFunc("/saml/auth", handler.RedirectBindingHandlerFunc(sp))
	http.HandleFunc("/metadata", handler.MetadaHandlerFunc(sp))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		ts, _ := template.New("sso").Parse(
			`<html><form method="GET" action="/saml/auth"><button type="submit">Submit</button></form></html>`,
		)

		ts.Execute(w, nil)
	})

	err = http.ListenAndServe(":8000", nil)
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Printf("failed to run demo: %s", err.Error())
		os.Exit(1)
	}
}
