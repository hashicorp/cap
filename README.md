# cap

`cap` (collection of authentication packages) provides a collection of related
packages which enable support for OIDC, JWT Verification and Distributed Claims.

**Please note**: We take security and our users' trust very seriously. If you 
believe you have found a security issue, please [responsibly
disclose](https://www.hashicorp.com/security#vulnerability-reporting) by
contacting us at  security@hashicorp.com.

## Contributing

Thank you for your interest in contributing! Please refer to
[CONTRIBUTING.md](https://github.com/hashicorp/cap/blob/main/CONTRIBUTING.md)
for guidance. 

<hr>

### [`oidc package`](./oidc) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/oidc.svg)](https://pkg.go.dev/github.com/hashicorp/cap/oidc)
 
 A package for writing clients that integrate with OIDC Providers. Primary types provided by the
 package are: 
 1. Request
 2. Token
 3. Config
 4. Provider 

The package also provides callbacks (in the form of http.HandlerFunc) for
handling OIDC provider responses to authorization code flow (with optional PKCE)
and implicit flow authentication attempts.
<hr>

Example of a provider using an authorization code flow:
```go
// Create a new provider config
pc, err := oidc.NewConfig(
    "http://your-issuer.com/",
    "your_client_id",
    "your_client_secret",
    []oidc.Alg{oidc.RS256},
    []string{"https://your_redirect_url"},
)
if err != nil {
    // handle error
}

// Create a provider
p, err := oidc.NewProvider(pc)
if err != nil {
    // handle error
}
defer p.Done()


// Create a Request for a user's authorization code flow authentication attempt, 
// with a 2 min timeout for  completion. 
oidcRequest, err := oidc.NewRequest(2 * time.Minute, "https://your_redirect_url")
if err != nil {
    // handle error
}


// Create an auth URL
authURL, err := p.AuthURL(ctx, oidcRequest)
if err != nil {
    // handle error
}
fmt.Println("open url to kick-off authentication: ", authURL)
```

Create a http.Handler for OIDC authentication response redirects.
```go
func NewHandler(ctx context.Context, p *oidc.Provider, r callback.RequestReader) (http.HandlerFunc, error)
    if p == nil { 
        // handle error
    }
    if rw == nil {
        // handle error
    }
    return func(w http.ResponseWriter, req *http.Request) {
        oidcRequest, err := rw.Read(ctx, req.FormValue("state"))
        if err != nil {
            // handle error
        }
        // Exchange(...) will verify the tokens before returning. 
        token, err := p.Exchange(ctx, oidcRequest, req.FormValue("state"), req.FormValue("code"))
        if err != nil {
            // handle error
        }
        var claims map[string]interface{}
        if err := token.IDToken().Claims(&claims); err != nil {
            // handle error
        }

        // Get the user's claims via the provider's UserInfo endpoint
        var infoClaims map[string]interface{}
        err = p.UserInfo(ctx, token.StaticTokenSource(), claims["sub"].(string), &infoClaims)
        if err != nil {
            // handle error
        }
        resp := struct {
		    IDTokenClaims  map[string]interface{}
		    UserInfoClaims map[string]interface{}
		}{claims, infoClaims}
		enc := json.NewEncoder(w)
		if err := enc.Encode(resp); err != nil {
			// handle error
        }
    }
}
```

### [`jwt package`](./jwt) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/jwt.svg)](https://pkg.go.dev/github.com/hashicorp/cap/jwt)

Package jwt provides signature verification and claims set validation for JSON Web Tokens (JWT)
of the JSON Web Signature (JWS) form.

JWT claims set validation provided by the package includes the option to validate
all registered claim names defined in [rfc7519#section-4.1](https://tools.ietf.org/html/rfc7519#section-4.1).

JOSE header validation provided by the the package includes the option to validate the "alg"
(Algorithm) Header Parameter defined in [rfc7515#section-4.1](https://tools.ietf.org/html/rfc7515#section-4.1).

JWT signature verification is supported by providing keys from the following sources:

- JSON Web Key Set (JWKS) URL
- OIDC Discovery mechanism
- Local public keys

JWT signature verification supports the following asymmetric algorithms defined in
[rfc7518.html#section-3.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1):
 
| Identifier | Signing Algorithm                              |
| ---------- | :--------------------------------------------- |
| RS256      | RSASSA-PKCS1-v1_5 using SHA-256                |
| RS384      | RSASSA-PKCS1-v1_5 using SHA-384                |
| RS512      | RSASSA-PKCS1-v1_5 using SHA-512                |
| ES256      | ECDSA using P-256 and SHA-256                  |
| ES384      | ECDSA using P-384 and SHA-384                  |
| ES512      | ECDSA using P-521 and SHA-512                  |
| PS256      | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |
| PS384      | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |
| PS512      | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |
| EdDSA      | Ed25519 using SHA-512                          |

<hr>

Example usage of JWT signature verification and claims set validation using keys from a JWKS URL:

```go
ctx := context.Background()

keySet, err := jwt.NewJSONWebKeySet(ctx, "your_jwks_url", "your_jwks_ca_pem")
if err != nil {
	log.Fatal(err)
}

validator, err := jwt.NewValidator(keySet)
if err != nil {
	log.Fatal(err)
}

expected := jwt.Expected{
	Issuer:            "your_expected_issuer",
	Subject:           "your_expected_subject",
	ID:                "your_expected_jwt_id",
	Audiences:         []string{"your_expected_audiences"},
	SigningAlgorithms: []jwt.Alg{jwt.RS256},
}

token := "header.payload.signature"
claims, err := validator.Validate(ctx, token, expected)
if err != nil {
	log.Fatal(err)
}
```

For additional documentation and usage examples, see [jwt/README.md](./jwt).


<hr>

### [`ldap package`](./ldap) 
[![Go
Reference](https://pkg.go.dev/badge/github.com/hashicorp/cap/ldap.svg)](https://pkg.go.dev/github.com/hashicorp/cap/ldap)

ldap is a package for writing clients that authenticate using Active Directory
or LDAP.

Primary types provided by the package:

* `ldap.Client`
* `ldap.ClientConfig`

<hr>

### Example usage

An abbreviated example of authenticating a user:

```go
client, err := ldap.NewClient(ctx, &clientConfig)
if err != nil { 
  // handle error appropriately
}

// authenticate and get the user's groups as well.
result, err := client.Authenticate(ctx, username, passwd, ldap.WithGroups())
if err != nil { 
  // handle error appropriately
}

if result.Success {
  // user successfully authenticated...
  if len(result.Groups) > 0 {
    // we found some groups associated with the authenticated user...
  }
}
```

### [`saml package`](./saml)

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

#### Example usage

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
