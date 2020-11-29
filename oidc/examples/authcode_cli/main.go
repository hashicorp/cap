package main

import (
	"context"
	"encoding/json"
	"errors"
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
	clientId     = "OIDC_CLIENT_ID"
	clientSecret = "OIDC_CLIENT_SECRET"
	issuer       = "OIDC_ISSUER"
	port         = "OIDC_PORT"
)

const attemptExp = "attemptExp"

func envConfig() (map[string]interface{}, error) {
	env := map[string]interface{}{
		clientId:     os.Getenv("OIDC_CLIENT_ID"),
		clientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		issuer:       os.Getenv("OIDC_ISSUER"),
		port:         os.Getenv("OIDC_PORT"),
		attemptExp:   time.Duration(2 * time.Minute),
	}
	for k, v := range env {
		switch t := v.(type) {
		case string:
			if t == "" {
				return nil, fmt.Errorf("%s is empty", k)
			}
		case time.Duration:
			if t == 0 {
				return nil, fmt.Errorf("%s is empty", k)
			}
		default:
			return nil, fmt.Errorf("%s is an unhandled type %t", k, t)
		}
	}
	return env, nil
}

func main() {
	env, err := envConfig()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, os.Interrupt)
	defer signal.Stop(sigintCh)

	pc, err := oidc.NewProviderConfig(env[issuer].(string), env[clientId].(string), oidc.ClientSecret(env[clientSecret].(string)), []oidc.Alg{oidc.RS256})
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}

	p, err := oidc.NewAuthCodeProvider(pc)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}
	defer p.Done()

	s, err := oidc.NewState(env[attemptExp].(time.Duration), fmt.Sprintf("http://localhost:%s/callback", env[port].(string)))
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}

	authUrl, err := p.AuthURL(context.Background(), s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
		return
	}

	successFn, successCh := success()
	errorFn, failedCh := failed()
	callback := callback.AuthCode(context.Background(), p, &callback.SingleStateReader{State: s}, successFn, errorFn)

	// Set up callback handler
	http.HandleFunc("/callback", callback)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", env[port]))
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return
	}
	defer listener.Close()

	// Open the default browser to the callback URL.
	fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Launching browser to:\n\n    %s\n\n\n", authUrl)
	if err := openURL(authUrl); err != nil {
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
		printClaims(resp.Token.IdToken())
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
	doneCh := make(chan successResp)
	return func(stateId string, t oidc.Token, w http.ResponseWriter) {
		var responseErr error
		defer func() {
			doneCh <- successResp{t, responseErr}
			close(doneCh)
		}()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(successHTML)); err != nil {
			responseErr = err
			fmt.Fprintf(os.Stderr, "error writing successful response: %s", err)
		}
	}, doneCh
}

func failed() (callback.ErrorResponseFunc, <-chan error) {
	doneCh := make(chan error)
	return func(stateId string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter) {
		var responseErr error
		defer func() {
			doneCh <- responseErr
			close(doneCh)
		}()

		if e != nil {
			fmt.Fprintf(os.Stderr, "callback error: %s", e.Error())
			responseErr = e
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r != nil {
			fmt.Fprintf(os.Stderr, "callback error from oidc provider: %s", r)
			responseErr = fmt.Errorf("callback error from oidc provider: %s", r)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		responseErr = errors.New("Unknown error from callback")
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
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read /proc/version.\n")
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
}

type respToken struct {
	IdToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

func printClaims(t oidc.IdToken) {
	var tokenClaims map[string]interface{}
	if err := t.Claims(&tokenClaims); err != nil {
		fmt.Fprintf(os.Stderr, "IdToken claims: error parsing: %s", err)
	} else {
		if idData, err := json.MarshalIndent(tokenClaims, "", "    "); err != nil {
			fmt.Fprint(os.Stderr, err)
		} else {
			fmt.Fprintf(os.Stderr, "IdToken claims:%s\n", idData)
		}
	}
}

func printUserInfo(p *oidc.AuthCodeProvider, t oidc.Token) {
	if t, ok := t.(interface {
		StaticTokenSource() oauth2.TokenSource
	}); ok {
		var infoClaims map[string]interface{}
		err := p.UserInfo(context.Background(), t.StaticTokenSource(), &infoClaims)
		if err != nil {
			fmt.Fprintf(os.Stderr, "channel received success, but error getting UserInfo claims: %s", err)
			return
		}
		infoData, err := json.MarshalIndent(infoClaims, "", "    ")
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			return
		}
		fmt.Fprintf(os.Stderr, "UserInfo claims:%s\n", infoData)
		return
	}
}

func printToken(t oidc.Token) {
	tokenData, err := json.MarshalIndent(printableToken(t), "", "    ")
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}
	fmt.Fprintf(os.Stderr, "channel received success.\nToken:%s\n", tokenData)
}

// printableToken is needed because the oidc.Token redacts the IdToken,
// AccessToken and RefreshToken
func printableToken(t oidc.Token) respToken {
	return respToken{
		IdToken:      string(t.IdToken()),
		AccessToken:  string(t.AccessToken()),
		RefreshToken: string(t.RefreshToken()),
		Expiry:       t.Expiry(),
	}
}
