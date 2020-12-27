module github.com/hashicorp/cap

go 1.15

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-uuid v1.0.2

	// TODO (jimlambrt 12/2020): move the examples into their own modules, which will remove this dep
	github.com/patrickmn/go-cache v2.1.0+incompatible
	// TODO (jimlambrt 12/2020): move the examples into their own modules, which will remove this dep
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/stretchr/testify v1.6.1
	github.com/yhat/scrape v0.0.0-20161128144610-24b7890b0945
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	golang.org/x/text v0.3.3
	gopkg.in/square/go-jose.v2 v2.5.1

)
