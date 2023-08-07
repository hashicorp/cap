package main

import (
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
		"entityID": os.Getenv("CAP_SAML_ENTITY_ID"),
		"acs":      os.Getenv("CAP_SAML_ACS"),
		"issuer":   os.Getenv("CAP_SAML_ISSUER"),
		"metadata": os.Getenv("CAP_SAML_METADATA"),
	}

	entityID, err := url.Parse(envs["entityID"])
	exitOnError(err)

	acs, err := url.Parse(envs["acs"])
	exitOnError(err)

	issuer, err := url.Parse(envs["issuer"])
	exitOnError(err)

	metadataURL, err := url.Parse(envs["metadata"])
	exitOnError(err)

	cfg, err := saml.NewConfig(entityID, acs, issuer, metadataURL)
	exitOnError(err)

	sp, err := saml.NewServiceProvider(cfg)
	exitOnError(err)

	http.HandleFunc("/saml/acs", handler.ACSHandlerFunc(sp))
	http.HandleFunc("/saml/auth", handler.RedirectBindingHandlerFunc(sp))
	http.HandleFunc("/metadata", handler.MetadaHandlerFunc(sp))

	http.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		ts, _ := template.New("sso").Parse(
			`<html><form method="GET" action="/saml/auth"><button type="submit">Submit</button></form></html>`,
		)

		ts.Execute(w, nil)
	})

	fmt.Println("Visit http://localhost:8000/login")

	err = http.ListenAndServe(":8000", nil)
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Printf("failed to run demo: %s", err.Error())
		os.Exit(1)
	}
}
