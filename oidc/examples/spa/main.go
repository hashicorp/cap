package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/hashicorp/cap/oidc"
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
				if !secretNotRequired && t == "" {
					return nil, fmt.Errorf("%s: %s is empty.\n\n   Did you intend to use -pkce or -implicit options?", op, k)
				}
				env[k] = "" // unsetting the secret which isn't required
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
	usePKCE := flag.Bool("pkce", false, "use the implicit flow")

	flag.Parse()
	if *useImplicit && *usePKCE {
		fmt.Fprint(os.Stderr, "you can't request both: -implicit and -pkce")
		return
	}

	env, err := envConfig(*useImplicit || *usePKCE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n\n", err)
		return
	}

	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, os.Interrupt)
	defer signal.Stop(sigintCh)

	issuer := env[issuer].(string)
	clientID := env[clientID].(string)
	clientSecret := oidc.ClientSecret(env[clientSecret].(string))
	redirectURL := fmt.Sprintf("http://localhost:%s/callback", env[port].(string))
	timeout := env[attemptExp].(time.Duration)

	sc := newStateCache(env[attemptExp].(time.Duration), timeout)

	pc, err := oidc.NewConfig(issuer, clientID, clientSecret, []oidc.Alg{oidc.RS256}, []string{redirectURL})
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

	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
		return
	}

	callback, err := CallbackHandler(context.Background(), p, sc, *useImplicit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating callback handler: %s", err)
		return
	}

	var stateOptions []oidc.Option
	switch {
	case *useImplicit:
		stateOptions = append(stateOptions, oidc.WithImplicitFlow())
	case *usePKCE:
		v, err := oidc.NewCodeVerifier()
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			return
		}
		stateOptions = append(stateOptions, oidc.WithPKCE(v))
	}

	// Set up callback handler
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/login", LoginHandler(context.Background(), p, sc, timeout, redirectURL, stateOptions))
	http.HandleFunc("/success", SuccessHandler(context.Background(), sc))

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", env[port]))
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}
	defer listener.Close()

	srvCh := make(chan error)
	// Start local server
	go func() {
		fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Launching browser to:\n\n    http://localhost:%s/login\n\n\n", env[port])
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
	case <-sigintCh:
		fmt.Fprintf(os.Stderr, "Interrupted")
		return
	}
}
