
# [`saml package`](./saml)

[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/saml.svg)](https://pkg.go.dev/github.com/hashicorp/cap/saml)

A package for writing clients that integrate with SAML Providers.

The SAML library orients mainly on the implementation profile for
[federation interoperability](https://kantarainitiative.github.io/SAMLprofiles/fedinterop.html)
(also known as interoperable SAML), a set of software conformance requirements
intended to facilitate interoperability within the context of full mesh identity
federations. It supports the Web Browser SSO profile with HTTP-Post and
HTTP-Redirect as supported service bindings. The default SAML settings follow
the requirements of the interoperable SAML
[deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html#_service_provider_requirements).

## Example usage

```go
    // Create a new saml config providing the necessary provider information:
    cfg, err := saml.NewConfig(<entityID>, <acs>, <metadata>, options...)
	// handle error

    // Use the config to create the service provider:
    sp, err := saml.NewServiceProvider(cfg)
    // handle error

    // With the service provider you can create saml authentication requests:

    // Generate a saml auth request with HTTP Post-Binding
    template, err := sp.AuthRequestPost("relay state", options...)
    // handle error

    // Generate a saml auth request with HTTP Request-Binding
    redirectURL, err := sp.AuthRequestRedirect("relay state", options...)
    // handle error

    // Parsing a SAML response:
    r.ParseForm()
    samlResp := r.PostForm.Get("SAMLResponse")

    response, err := sp.ParseResponse(samlResp, "Response ID", options...)
    // handle error
```

You can find the full demo code in the [`saml/demo`](./saml/demo/main.go)
package.
