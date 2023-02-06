// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
	"github.com/hashicorp/cap/util"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
)

// List of required configuration environment variables
const (
	clientID     = "OIDC_CLIENT_ID"
	clientSecret = "OIDC_CLIENT_SECRET"
	issuer       = "OIDC_ISSUER"
	port         = "OIDC_PORT"
	attemptExp   = "attemptExp"
)

func envConfig(secretNotRequired bool) (map[string]interface{}, error) {
	const op = "envConfig"
	env := map[string]interface{}{
		clientID:     os.Getenv("OIDC_CLIENT_ID"),
		clientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		issuer:       os.Getenv("OIDC_ISSUER"),
		port:         os.Getenv("OIDC_PORT"),
		attemptExp:   time.Duration(2 * time.Minute),
	}
	for k, v := range env {
		switch t := v.(type) {
		case string:
			switch k {
			case "OIDC_CLIENT_SECRET":
				switch {
				case secretNotRequired:
					env[k] = "" // unsetting the secret which isn't required
				case t == "":
					return nil, fmt.Errorf("%s: %s is empty.\n\n   Did you intend to use -pkce or -implicit options?", op, k)
				}
			default:
				if t == "" {
					return nil, fmt.Errorf("%s: %s is empty", op, k)
				}
			}
		case time.Duration:
			if t == 0 {
				return nil, fmt.Errorf("%s: %s is empty", op, k)
			}
		default:
			return nil, fmt.Errorf("%s: %s is an unhandled type %t", op, k, t)
		}
	}
	return env, nil
}

func main() {
	useImplicit := flag.Bool("implicit", false, "use the implicit flow")
	implicitAccessToken := flag.Bool("implicit-access-token", false, "include the access_token in the implicit flow")
	usePKCE := flag.Bool("pkce", false, "use the implicit flow")
	maxAge := flag.Int("max-age", -1, "max age of user authentication")
	scopes := flag.String("scopes", "", "comma separated list of additional scopes to requests")
	useTestProvider := flag.Bool("use-test-provider", false, "use the test oidc provider")

	flag.Parse()
	if *useImplicit && *usePKCE {
		fmt.Fprint(os.Stderr, "you can't request both: -implicit and -pkce")
		return
	}

	if (*useImplicit || *implicitAccessToken || *scopes != "") && *useTestProvider {
		fmt.Fprint(os.Stderr, "you can't use the implicit flow, PKCE or scopes with the test provider")
		return
	}

	optScopes := strings.Split(*scopes, ",")
	for i := range optScopes {
		optScopes[i] = strings.TrimSpace(optScopes[i])
	}

	var env map[string]interface{}
	var tp *oidc.TestProvider
	if *useTestProvider {
		l, err := oidc.NewTestingLogger(hclog.New(nil))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
			return
		}
		// Generate a key to sign JWTs with throughout most test cases
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
			return
		}
		oidcPort := os.Getenv("OIDC_PORT")
		if oidcPort == "" {
			fmt.Fprintf(os.Stderr, "env OIDC_PORT is empty")
			return
		}

		id, secret := "test-rp", "fido"
		tp = oidc.StartTestProvider(l, oidc.WithNoTLS(), oidc.WithTestDefaults(&oidc.TestProviderDefaults{
			CustomClaims: map[string]interface{}{},
			SubjectInfo: map[string]*oidc.TestSubject{
				"alice": {
					Password: "fido",
					UserInfo: map[string]interface{}{
						"email":  "alice@example.com",
						"name":   "alice smith",
						"friend": "eve",
					},
					CustomClaims: map[string]interface{}{
						"email": "alice@example.com",
						"name":  "alice smith",
					},
				},
				"eve": {
					Password: "alice",
					UserInfo: map[string]interface{}{
						"email":  "eve@example.com",
						"name":   "eve smith",
						"friend": "alice",
					},
					CustomClaims: map[string]interface{}{
						"email": "eve@example.com",
						"name":  "eve smith",
					},
				},
			},
			SigningKey: &oidc.TestSigningKey{
				PrivKey: priv,
				PubKey:  priv.Public(),
				Alg:     oidc.ES384,
			},
			AllowedRedirectURIs: []string{fmt.Sprintf("http://localhost:%s/callback", oidcPort)},
			ClientID:            &id,
			ClientSecret:        &secret,
		}))
		defer tp.Stop()
		env = map[string]interface{}{
			clientID:     id,
			clientSecret: secret,
			issuer:       tp.Addr(),
			port:         oidcPort,
			attemptExp:   time.Duration(2 * time.Minute),
		}
	} else {
		var err error
		env, err = envConfig(*useImplicit || *usePKCE)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
			return
		}
	}

	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, os.Interrupt)
	defer signal.Stop(sigintCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	issuer := env[issuer].(string)
	clientID := env[clientID].(string)
	clientSecret := oidc.ClientSecret(env[clientSecret].(string))
	redirectURL := fmt.Sprintf("http://localhost:%s/callback", env[port].(string))
	pc, err := oidc.NewConfig(issuer, clientID, clientSecret, []oidc.Alg{oidc.ES384}, []string{redirectURL})
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}

	p, err := oidc.NewProvider(pc)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}
	defer p.Done()

	var requestOptions []oidc.Option
	switch {
	case *useImplicit && !*implicitAccessToken:
		requestOptions = append(requestOptions, oidc.WithImplicitFlow())
	case *useImplicit && *implicitAccessToken:
		requestOptions = append(requestOptions, oidc.WithImplicitFlow(true))
	case *usePKCE:
		v, err := oidc.NewCodeVerifier()
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			return
		}
		requestOptions = append(requestOptions, oidc.WithPKCE(v))
	}

	if *maxAge >= 0 {
		requestOptions = append(requestOptions, oidc.WithMaxAge(uint(*maxAge)))
	}

	requestOptions = append(requestOptions, oidc.WithScopes(optScopes...))

	oidcRequest, err := oidc.NewRequest(env[attemptExp].(time.Duration), redirectURL, requestOptions...)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}

	successFn, successCh := success()
	errorFn, failedCh := failed()

	var handler http.HandlerFunc
	if *useImplicit {
		handler, err = callback.Implicit(ctx, p, &callback.SingleRequestReader{Request: oidcRequest}, successFn, errorFn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating callback handler: %s", err)
			return
		}
	} else {
		handler, err = callback.AuthCode(ctx, p, &callback.SingleRequestReader{Request: oidcRequest}, successFn, errorFn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating auth code handler: %s", err)
			return
		}
	}

	authURL, err := p.AuthURL(ctx, oidcRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
		return
	}

	// Set up callback handler
	http.HandleFunc("/callback", handler)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", env[port]))
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}
	defer listener.Close()

	// Open the default browser to the callback URL.
	fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Launching browser to:\n\n    %s\n\n\n", authURL)
	if err := util.OpenURL(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error attempting to automatically open browser: '%s'.\nPlease visit the authorization URL manually.", err)
	}

	srvCh := make(chan error)
	// Start local server
	go func() {
		err := http.Serve(listener, nil)
		if err != nil && err != http.ErrServerClosed {
			srvCh <- err
		}
	}()

	// Wait for either the callback to finish, SIGINT to be received or up to 2 minutes
	select {
	case err := <-srvCh:
		fmt.Fprintf(os.Stderr, "server closed with error: %s", err.Error())
		return
	case resp := <-successCh:
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "channel received success with error: %s", resp.Error)
			return
		}
		printToken(resp.Token)
		printClaims(resp.Token.IDToken())
		printUserInfo(ctx, p, resp.Token)
		return
	case err := <-failedCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "channel received error: %s", err)
			return
		}
		fmt.Fprint(os.Stderr, "missing error from error channel.  try again?\n")
		return
	case <-sigintCh:
		fmt.Fprintf(os.Stderr, "Interrupted")
		return
	case <-time.After(env[attemptExp].(time.Duration)):
		fmt.Fprintf(os.Stderr, "Timed out waiting for response from provider")
		return
	}
}

type successResp struct {
	Token oidc.Token // Token is populated when the callback successfully exchanges the auth code.
	Error error      // Error is populated when there's an error during the callback
}

func success() (callback.SuccessResponseFunc, <-chan successResp) {
	const op = "success"
	doneCh := make(chan successResp)
	return func(state string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		var responseErr error
		defer func() {
			doneCh <- successResp{t, responseErr}
			close(doneCh)
		}()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(successHTML)); err != nil {
			responseErr = fmt.Errorf("%s: %w", op, err)
			fmt.Fprintf(os.Stderr, "error writing successful response: %s", err)
		}
	}, doneCh
}

func failed() (callback.ErrorResponseFunc, <-chan error) {
	const op = "failed"
	doneCh := make(chan error)
	return func(state string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
		var responseErr error
		defer func() {
			if _, err := w.Write([]byte(responseErr.Error())); err != nil {
				fmt.Fprintf(os.Stderr, "%s: error writing failed response: %s", op, err)
			}
			doneCh <- responseErr
			close(doneCh)
		}()

		if e != nil {
			fmt.Fprintf(os.Stderr, "%s: callback error: %s", op, e.Error())
			responseErr = e
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r != nil {
			responseErr = fmt.Errorf("%s: callback error from oidc provider: %s", op, r)
			fmt.Fprint(os.Stderr, responseErr.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		responseErr = fmt.Errorf("%s: unknown error from callback", op)
	}, doneCh
}

type respToken struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

func printClaims(t oidc.IDToken) {
	const op = "printClaims"
	var tokenClaims map[string]interface{}
	if err := t.Claims(&tokenClaims); err != nil {
		fmt.Fprintf(os.Stderr, "IDToken claims: error parsing: %s", err)
	} else {
		if idData, err := json.MarshalIndent(tokenClaims, "", "    "); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s", op, err)
		} else {
			fmt.Fprintf(os.Stderr, "IDToken claims:%s\n", idData)
		}
	}
}

func printUserInfo(ctx context.Context, p *oidc.Provider, t oidc.Token) {
	const op = "printUserInfo"
	if ts, ok := t.(interface {
		StaticTokenSource() oauth2.TokenSource
	}); ok {
		if ts.StaticTokenSource() == nil {
			fmt.Fprintf(os.Stderr, "%s: no access_token received, so we're unable to get UserInfo claims", op)
			return
		}
		vc := struct {
			Sub string
		}{}
		if err := t.IDToken().Claims(&vc); err != nil {
			fmt.Fprintf(os.Stderr, "%s: channel received success, but error getting UserInfo claims: %s", op, err)
			return
		}
		var infoClaims map[string]interface{}
		err := p.UserInfo(ctx, ts.StaticTokenSource(), vc.Sub, &infoClaims)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: channel received success, but error getting UserInfo claims: %s", op, err)
			return
		}
		infoData, err := json.MarshalIndent(infoClaims, "", "    ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s", op, err)
			return
		}
		fmt.Fprintf(os.Stderr, "UserInfo claims:%s\n", infoData)
		return
	}
}

func printToken(t oidc.Token) {
	const op = "printToken"
	tokenData, err := json.MarshalIndent(printableToken(t), "", "    ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s", op, err)
		return
	}
	fmt.Fprintf(os.Stderr, "channel received success.\nToken:%s\n", tokenData)
}

// printableToken is needed because the oidc.Token redacts the IDToken,
// AccessToken and RefreshToken
func printableToken(t oidc.Token) respToken {
	return respToken{
		IDToken:      string(t.IDToken()),
		AccessToken:  string(t.AccessToken()),
		RefreshToken: string(t.RefreshToken()),
		Expiry:       t.Expiry(),
	}
}
