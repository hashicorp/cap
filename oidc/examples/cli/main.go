package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
	"golang.org/x/oauth2"
)

// List of required configuration environment variables
const (
	clientID     = "OIDC_CLIENT_ID"
	clientSecret = "OIDC_CLIENT_SECRET"
	issuer       = "OIDC_ISSUER"
	port         = "OIDC_PORT"
)

const attemptExp = "attemptExp"

func envConfig(useImplicit bool) (map[string]interface{}, error) {
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
				if !useImplicit && t == "" {
					return nil, fmt.Errorf("%s: %s is empty", op, k)
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
	flag.Parse()

	env, err := envConfig(*useImplicit)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
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

	var stateOption oidc.Option
	if *useImplicit {
		stateOption = oidc.WithImplicitFlow()
	}
	s, err := oidc.NewState(env[attemptExp].(time.Duration), redirectURL, stateOption)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}

	successFn, successCh := success()
	errorFn, failedCh := failed()

	var handler http.HandlerFunc
	if *useImplicit {
		handler, err = callback.Implicit(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating callback handler: %s", err)
			return
		}
	} else {
		handler, err = callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating auth code handler: %s", err)
			return
		}
	}

	authURL, err := p.AuthURL(context.Background(), s)
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
	if err := openURL(authURL); err != nil {
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
		printUserInfo(p, resp.Token)
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
	return func(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
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
	return func(stateID string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
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

// openURL opens the specified URL in the default browser of the user.
// source: https://github.com/hashicorp/vault-plugin-auth-jw
func openURL(url string) error {
	var cmd string
	var args []string

	switch {
	case "windows" == runtime.GOOS || isWSL():
		cmd = "cmd.exe"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin" == runtime.GOOS:
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

// isWSL tests if the binary is being run in Windows Subsystem for Linux
// source: https://github.com/hashicorp/vault-plugin-auth-jwt
func isWSL() bool {
	const op = "isWSL"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: unable to read /proc/version.\n", op)
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
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

func printUserInfo(p *oidc.Provider, t oidc.Token) {
	const op = "printUserInfo"
	if t, ok := t.(interface {
		StaticTokenSource() oauth2.TokenSource
	}); ok {
		if t.StaticTokenSource() == nil {
			fmt.Fprintf(os.Stderr, "%s: no access_token received, so we're unable to get UserInfo claims", op)
			return
		}
		var infoClaims map[string]interface{}
		err := p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
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
