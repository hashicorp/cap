# cap

The `cap` provides a collection of authentication packages related to OIDC, JWKs and Distributed Claims.

### [`oidc`](./oidc)
 A package for writing OIDC Provider integrations. Primary types provided by the
 package are: 
 1. State
 2. Token
 3. Config
 4. Provider 

The package also provides callbacks (in the form of http.HandlerFunc) for
handling OIDC provider responses to authorization code flow (with optional PKCE)
and implicit flow authentication attempts.

Example for a provider using an authorization code flow:
```go
// Create a new Config for provider that will only use the authorizat
pc, _ := oidc.NewConfig(
    Issuer:                 "http://your-issuer.com/",
    ClientID:               "your_client_id",
    ClientSecret:           "your_client_secret",
    SupportedSigningAlgs:   []oidc.Alg{oidc.RS256},
    AllowedRedirectURLs:    []string{"http://your_redirect_url"},
)

// Create a provider
p, _ := oidc.NewProvider(pc)
defer p.Done()


// Create a State for a user's authentication attempt 
ttl := 2 * time.Minute
s, _ := oidc.NewState(ttl, "http://your_redirect_url")


// Create an auth URL
authURL, _ := p.AuthURL(context.Background(), s)
fmt.Println("open url to kick-off authentication: ", authURL)


// Exchange a successful authentication's authorization code and state (received 
// in a callback) for a verified Token.
t, _ := p.Exchange(context.Background(), s, "authorization-state", "authorization-code")
fmt.Printf("id_token: %v\n", string(t.IDToken()))


// Get the user's claims via the provider's UserInfo endpoint
var infoClaims map[string]interface{}
_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
fmt.Println("UserInfo claims: ", infoClaims)
````
  
 