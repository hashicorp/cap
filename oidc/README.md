# oidc

oidc is a package for writing OIDC Provider integrations using OIDC flows
(initially only the authorization code has been implemented).  


### Example OIDC Authorization Code flow usage:

<hr>

Create an authorization code URL for your CLI/UI to initiate the authentication flow by opening the URL in a browser.

```go
pc, err := oidc.NewProviderConfig("https://YOUR_DOMAIN/", "YOUR_CLIENT_ID", "YOUR_CLIENT_SECRET", []oidc.Alg{oidc.RS256})
if err != nil {
		log.Printf("failed to configure provider: %s", err)
		return nil, err
}

p, err := oidc.NewAuthCodeProvider(pc)
if err != nil {
		log.Printf("failed to create new provider: %s", err)
		return nil, err
}
defer p.Done()

userAuthTimeout := 2 * time.Minute
redirectURL := "http://localhost:3000/callback"
s, err := oidc.NewState(userAuthTimeout, , redirectURL)
if err != nil {
    log.Printf("failed to create new oidc flow state: %s", err)
    return
}

// Important: you need to store "s", the State that's created for this authentication 
// attempt and make it available to your redirect callback via a callback.StateReader
authUrl, err := p.AuthURL(context.Background(), s)
if err != nil {
    log.Printf("error getting auth url: %s", err)
    return
}
```

Create a callback to handle the provider's redirect after the user succeeds or
fails to authenticate using the authorization Code URL.

```go
// successFn will handle successful authentications.
successFn :=  func(stateId string, t oidc.Token, w http.ResponseWriter) { 
    printableToken := struct {
        IdToken         string
        AccessToken     string
        RefreshToken    string
        Expiry          time.Time
    }{
        string(t.IdToken()),
        string(t.AccessToken()),
        string(t.RefreshToken()),
        t.Expiry(),
    }
	   
    tokenData, err := json.MarshalIndent(printableToken(t), "", "    ")
	if err != nil {
        log.Printf("failed to marshal JSON: %s", err)
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte("problem processing response JSON")
		return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(tokenData)) 
}
// errorFn will handle failed authentications or callback errors
errorFn := func(stateId string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter) {
    var responseErr error
    defer func() {
        if _, err := w.Write([]byte(responseErr.Error())); err != nil {
			log.Printf("error writing failed response: %s", err)
		}
    }()

    if e != nil {
        log.Printf("callback error: %s", e.Error())
        responseErr = e
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    if r != nil {
        log.Printf("callback error from oidc provider: %s", r)
        responseErr = fmt.Errorf("callback error from oidc provider: %s", r)
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    responseErr = errors.New("Unknown error from callback")
}

// callback.AuthCode will verify the token's returned for successful authentications.  
// The "stateReader" in the example is whatever you wish to use that implements the 
// callback.StateReader interface and contains the states used to create the AuthURLs
// for this callback.  
callback := callback.AuthCode(context.Background(), p, stateReader, successFn, errorFn)

// Set up callback handler
http.HandleFunc("/callback", callback)
```
