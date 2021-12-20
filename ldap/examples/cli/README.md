# cli

An example LDAP user authentication CLI that also retrieves the user's groups.
<hr>

## Running the CLI
```
go build
```
Running the cli requires providing the username for authentication.
```
./cli -username <username>
```
<hr>

### Using the built-in LDAP directory service

We've add support to use a built in test LDAP directory into the CLI example.

When you run the cli without specifying a config file, the test directory
will be configured and started on an available localhost port.  

The test directory only allows you to login with one user which is `alice` with a password
of `password`.  

This very simple Test Directory option removes the dependency of
standing up your own Directory, if you just want to run the CLI and see it work.

<hr>

### Using your own directory service. 
If you wish to use your own directory with the cli, then provide a json
configuration file via `--config
<filename>`.  

See the `ldap.ClientConfig` for the available configuration settings. \

An example of how this might be done is include, which can be executed by:
* Starting a local openldap service in docker using: `./start-local-ldap.sh`
* Then authenticating via: `./cli --config local-ldap-config.json --username "Hermes Conrad"`  then provide the password of `hermes` when
  prompted. 

<hr>



