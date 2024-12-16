module github.com/hashicorp/cap/saml

go 1.20

require (
	github.com/beevik/etree v1.2.0
	github.com/crewjam/go-xmlsec v0.0.0-20200414151428-d2b1a58f7262
	github.com/crewjam/saml v0.4.14
	github.com/hashicorp/go-uuid v1.0.3
	github.com/jonboulle/clockwork v0.4.0
	github.com/russellhaering/gosaml2 v0.9.1
	github.com/russellhaering/goxmldsig v1.4.0
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/crewjam/errset v0.0.0-20160219153700-f78d65de925c // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ma314smith/signedxml v1.1.1 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ma314smith/signedxml v1.1.1 => github.com/moov-io/signedxml v1.1.1
