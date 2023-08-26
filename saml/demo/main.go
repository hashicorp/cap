package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/hashicorp/cap/saml"
	"github.com/hashicorp/cap/saml/handler"
)

func main() {
	envs := map[string]string{
		"entityID":     os.Getenv("CAP_SAML_ENTITY_ID"),
		"acs":          os.Getenv("CAP_SAML_ACS"),
		"metadata":     os.Getenv("CAP_SAML_METADATA"),
		"metadata_xml": os.Getenv("CAP_SAML_METADATA_XML"),
	}

	var options []saml.Option
	if metaXML, ok := envs["metadata_xml"]; ok {
		options = append(options, saml.WithMetadataXML(metaXML))
	}

	cfg, err := saml.NewConfig(envs["entityID"], envs["acs"], envs["metadata"], options...)
	exitOnError(err)

	sp, err := saml.NewServiceProvider(cfg)
	exitOnError(err)

	http.HandleFunc("/saml/acs", handler.ACSHandlerFunc(sp))
	http.HandleFunc("/saml/auth/redirect", handler.RedirectBindingHandlerFunc(sp))
	http.HandleFunc("/saml/auth/post", handler.PostBindingHandlerFunc(sp))
	http.HandleFunc("/metadata", handler.MetadataHandlerFunc(sp))
	http.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		ts, _ := template.New("sso").Parse(
			`<html><form method="GET" action="/saml/auth/redirect"><button type="submit">Submit Redirect</button></form></html>
			<html><form method="GET" action="/saml/auth/post"><button type="submit">Submit POST</button></form></html>`,
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
