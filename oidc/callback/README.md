# callback

The callback package includes handlers (http.HandlerFunc) which can be used
for the callback leg an OIDC flow. Callback handlers for both the authorization
code flow (with optional PKCE) and the implicit flow are provided.

<hr>

### Example snippets...

```go
	// Create a new Config
	pc, _ := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback", "http://your_redirect_url/implicit-callback"},
	)

	// Create a provider
	p, _ := oidc.NewProvider(pc)
	defer p.Done()

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	ttl := 2 * time.Minute
	authCodeAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/auth-code-callback")

	// Create a State for a user's authentication attempt using an implicit
	// flow.
	implicitAttempt, _ := oidc.NewState(ttl, "http://your_redirect_url/implicit-callback")

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

	// create the authorization code callback and register it for use.
	authCodeCallback, _ := AuthCode(context.Background(), p, &SingleStateReader{State: authCodeAttempt}, successFn, errorFn)
	http.HandleFunc("/auth-code-callback", authCodeCallback)

	// create an implicit flow callback and register it for use.
	implicitCallback, _ := Implicit(context.Background(), p, &SingleStateReader{State: implicitAttempt}, successFn, errorFn)
	http.HandleFunc("/implicit-callback", implicitCallback)
```
