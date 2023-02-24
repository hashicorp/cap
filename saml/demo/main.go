package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/handler"
)

func main() {
	cfg := saml.NewConfig(
		"http://saml.julz/example",
		"http://localhost:8000/saml/acs",
		"https://samltest.id",
		"https://samltest.id/saml/idp",
	)

	sp, err := saml.NewServiceProvider(cfg)
	exitOnError(err)

	http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("SAML Response received")
	})

	http.HandleFunc("/saml/auth", handler.RequestHandler(sp))

	http.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		meta := sp.CreateSPMetadata()
		xml.NewEncoder(w).Encode(meta)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		ts, err := template.New("sso").Parse(
			`<html><form method="GET" action="/saml/auth"><button type="submit">Submit</button></form></html>`,
		)
		if err != nil {
			panic(err)
		}

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
