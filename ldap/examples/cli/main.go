package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/cap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/password"
)

func main() {

	// collect the username and password from the cli
	username := flag.String("username", "", "username to authenticate")
	cfgFilename := flag.String("config", "", "config filename")
	flag.Parse()
	if *username == "" {
		fmt.Fprintf(os.Stderr, "you must specify a --username\n")
		return
	}
	var clientConfig ldap.ClientConfig
	if *cfgFilename == "" {
		td := startTestDirectory()
		defer func() { td.Stop() }()
		clientConfig = ldap.ClientConfig{
			URLs:        []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificate: td.Cert(),
			DiscoverDN:  true,
			UserDN:      ldap.TestDefaultUserDN,
			GroupDN:     ldap.TestDefaultGroupDN,
		}
	} else {
		configFile, err := os.Open(*cfgFilename)
		defer configFile.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
		jsonParser := json.NewDecoder(configFile)
		if err := jsonParser.Decode(&clientConfig); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Enter password: ")
	value, err := password.Read(os.Stdin)
	fmt.Print("\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error())
		return
	}

	// create an ldap client for authentication
	ctx := context.Background()
	client, err := ldap.NewClient(ctx, &clientConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "An error occurred creating the ldap client:\n%s\n", err)
		return
	}
	defer func() { client.Close(ctx) }()

	// authenticate the user
	result, err := client.Authenticate(ctx, *username, value, ldap.WithGroups())
	if err != nil {
		fmt.Fprintf(os.Stderr, "An error occurred during authentication:\n%s\n", err.Error())
		return
	}

	// display the results
	if result.Success {
		fmt.Fprintf(os.Stdout, "authentication was successful for username: %s\n", *username)
		if len(result.Groups) > 0 {
			fmt.Fprintf(os.Stdout, "they belong to groups: %s", result.Groups)
		}
	}
}

func startTestDirectory() *ldap.TestDirectory {
	// start a test directory for the example
	t := &ldap.TestingLogger{Logger: hclog.Default()}
	td := ldap.StartTestDirectory(t, ldap.WithTestDirectoryDefaults(&ldap.TestDirectoryDefaults{AllowAnonymousBind: true}))
	td.SetGroups(ldap.TestGroup(t, "admin", []string{"alice"}))
	td.SetUsers(ldap.TestUsers(t, []string{"alice", "bob"})...)
	return td
}
