# callback

The callback package includes handlers (http.HandlerFunc) which can be used
for the callback leg an OIDC flow. Callback handlers for both the authorization
code flow (with optional PKCE) and the implicit flow are provided.

<hr>

### Example snippets...

```go
	ctx := context.Background()
	// Create a new Config
	pc, err := oidc.NewConfig(
		"http://your-issuer.com/",
		"your_client_id",
		"your_client_secret",
		[]oidc.Alg{oidc.RS256},
		[]string{"http://your_redirect_url/auth-code-callback", "http://your_redirect_url/implicit-callback"},
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

	// Create a State for a user's authentication attempt that will use the
	// authorization code flow.  (See NewState(...) using the WithPKCE and
	// WithImplicit options for creating a State that uses those flows.)
	ttl := 2 * time.Minute
    authCodeAttempt, err := oidc.NewState(ttl, "http://your_redirect_url/auth-code-callback")
	if err != nil {
		// handle error
	}

	// Create a State for a user's authentication attempt using an implicit
	// flow.
    implicitAttempt, err := oidc.NewState(ttl, "http://your_redirect_url/implicit-callback")
	if err != nil {
		// handle error
	}

	// A function to handle successful attempts from callback.
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

	// A function to handle errors and failed attempts from **callback**.
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
    authCodeCallback, err := AuthCode(ctx, p, &SingleStateReader{State: authCodeAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/auth-code-callback", authCodeCallback)

	// create an implicit flow callback and register it for use.
    implicitCallback, err := Implicit(ctx, p, &SingleStateReader{State: implicitAttempt}, successFn, errorFn)
	if err != nil {
		// handle error
	}
	http.HandleFunc("/implicit-callback", implicitCallback)
```
