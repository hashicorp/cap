// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	"github.com/jimlambrt/gldap/testdirectory"
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
			URLs:         []string{fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())},
			Certificates: []string{td.Cert()},
			DiscoverDN:   true,
			UserDN:       testdirectory.DefaultUserDN,
			GroupDN:      testdirectory.DefaultGroupDN,
		}
	} else {
		configFile, err := os.Open(*cfgFilename)
		defer configFile.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			return
		}
		jsonParser := json.NewDecoder(configFile)
		if err := jsonParser.Decode(&clientConfig); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
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

func startTestDirectory() *testdirectory.Directory {
	// start a test directory for the example
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "testdirectory-logger",
		Level: hclog.Error,
	})
	t := &testdirectory.Logger{Logger: logger}
	td := testdirectory.Start(t, testdirectory.WithLogger(t, logger), testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}))
	td.SetGroups(testdirectory.NewGroup(t, "admin", []string{"alice"}))
	td.SetUsers(testdirectory.NewUsers(t, []string{"alice", "bob"})...)
	return td
}
