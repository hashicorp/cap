# oidc

oidc is a package for writing OIDC Provider integrations using OIDC flows
(initially only the authorization code has been implemented).  

Primary types provided by the package:

* `State`: represents one OIDC authentication flow for a user.  It contains the
  data needed to uniquely represent that one-time flow across the multiple
  interactions needed to complete the OIDC flow the user is attempting.  All
  States contain an expiration for the user's OIDC flow.

* `Token`: represents an OIDC id_token, as well as an Oauth2 access_token and
  refresh_token (including the the access_token expiry)

* `Config`: provides the configuration for a typical 3-legged OIDC
  authorization code flow (for example: client ID/Secret, redirectURL, supported
  signing algorithms, additional scopes requested, etc)

* `Provider`: provides integration with an OIDC provider. 
  The provider provides capabilities like: generating an auth URL, exchanging
  codes for tokens, verifying tokens, making user info requests, etc.

* `Alg`: represents asymmetric signing algorithms

* `Error`: provides an error and provides the ability to specify an error code,
  operation that raised the error, the kind of error, and any wrapped error

#### `oidc.callback`
The callback package includes the ability to create a `http.HandlerFunc` which can be used
for the 3rd leg of the OIDC flow where the authorization code is exchanged for
tokens.   

<hr>

### Examples apps:

* [CLI example](examples/cli/) which implements an OIDC
  user authentication CLI.  

* [SPA example](examples/spa) which implements an OIDC user
  authentication SPA (single page app). 

### Example snippets...

```go
// Create a new Config
pc, _ := oidc.NewConfig(
"http://YOUR_ISSUER/",
"YOUR_CLIENT_ID",
"YOUR_CLIENT_SECRET",
[]oidc.Alg{oidc.RS256},
"http://YOUR_REDIRECT_URL",
)

// Create a provider
p, _ := oidc.NewProvider(pc)
defer p.Done()

// Create a State for a user's authentication attempt
ttl := 2 * time.Minute
s, _ := oidc.NewState(ttl)

// Create an auth URL from the provider using the user's auth attempt state
authURL, _ := p.AuthURL(context.Background(), s)
fmt.Println("open url to kick-off authentication: ", authURL)

// Exchange an authorizationCode and authorizationState received via a
// callback from successful oidc authentication response for a verified
// Token.
t, _ := p.Exchange(context.Background(), s, "RECEIVED_STATE", "RECEIVED_CODE")
fmt.Printf("id_token: %v\n", string(t.IDToken()))

// Create an auth code callback
successFn := func(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
w.WriteHeader(http.StatusOK)
printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
_, _ = w.Write([]byte(printableToken))
}
errorFn := func(stateID string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
if e != nil {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(e.Error()))
	return
}
w.WriteHeader(http.StatusUnauthorized)
}
callback := callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
http.HandleFunc("/callback", callback)

// Get the user's claims via the UserInfo endpoint
var infoClaims map[string]interface{}
_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
fmt.Println("UserInfo claims: ", infoClaims)

```
