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

#### [oidc.callback](callback/)
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
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url"},
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	
	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)	
  ttl := 2 * time.Minute
	s, _ := oidc.NewState(ttl, "http://your_redirect_url")

	// Create an auth URL
	authURL, _ := p.AuthURL(context.Background(), s)
	fmt.Println("open url to kick-off authentication: ", authURL)

	// Exchange a successful authentication's authorization code and
	// authorization state (received in a callback) for a verified Token.
	t, _ := p.Exchange(context.Background(), s, "authorization-state", "authorization-code")
	fmt.Printf("id_token: %v\n", string(t.IDToken()))

	// Create an authorization code flow callback
	// A function to handle successful attempts.
	successFn := func(
		stateID string,
		t oidc.Token,
		w http.ResponseWriter,
		req *http.Request,
	) {
		w.WriteHeader(http.StatusOK)
		printableToken := fmt.Sprintf("id_token: %s", string(t.IDToken()))
		_, _ = w.Write([]byte(printableToken))
	}
	// A function to handle errors and failed attempts.
	errorFn := func(
		stateID string,
		r *callback.AuthenErrorResponse,
		e error,
		w http.ResponseWriter,
		req *http.Request,
	) {
		if e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(e.Error()))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	// create the callback and register it for use.
	callback, _ := callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
	http.HandleFunc("/callback", callback)

	// Get the user's claims via the provider's UserInfo endpoint
	var infoClaims map[string]interface{}
	_ = p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
	fmt.Println("UserInfo claims: ", infoClaims)
```
