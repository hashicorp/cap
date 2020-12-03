module github.com/hashicorp/cap/oidc

go 1.15

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/vault/sdk v0.1.13

	// TODO (jimlambrt 12/2020): move the examples into their own modules, which will remove this dep
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pquerna/cachecontrol v0.0.0-20200921180117-858c6e7e6b7e // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
)
