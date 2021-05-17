module github.com/hashicorp/cap

go 1.15

require (
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/fatih/color v1.11.0 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v0.16.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/stretchr/testify v1.7.0
	github.com/yhat/scrape v0.0.0-20161128144610-24b7890b0945
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
	golang.org/x/net v0.0.0-20210510120150-4163338589ed
	// TODO: golang.org/x/oauth2 intentionally pinned to version that doesn't
	//       depend on google.golang.org/grpc v1.30.0 or higher due to the issue
	//       opened at: https://github.com/etcd-io/etcd/issues/12124
	//
	// Note: this may be resolved soon with the release of etcd v3.5.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015 // indirect
	golang.org/x/text v0.3.6
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
