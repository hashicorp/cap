# cli

An example OIDC user authentication CLI that supports both the authorization
code (with optional PKCE) and implicit OIDC flows.

<hr>

## Running the CLI
```
go build
```
Without any flags, the cli will invoke an authorization code authentication. 
```
./cli
```

With the `-pkce` flag, the cli will invoke an authorization code with PKCE authentication. 
```
./cli -pkce
```

With the `-implicit` flag, the cli will invoke an implicit flow authentication. 
```
./cli -implicit
```

With the `-max-age` flag, the cli will require an authentication not older than
the max-age specified in seconds. 
```
./cli -max-age <seconds>
```
### Required environment variables
(required if not using the built-in Test Provider. see note below on how-to use this option)

* `OIDC_CLIENT_ID`: Your Relying Party client id.
* `OIDC_CLIENT_SECRET`: Your Rely Party secret (this is not required for implicit
  flows or authorization code with PKCE flows)
* `OIDC_ISSUER`: The OIDC issuer identifier (aka the discover URL)
* `OIDC_PORT`: The port you'd like to use for your callback HTTP listener.

<hr>

### OIDC Provider

You must configure your provider's allowed callbacks to include:
`http://localhost:{OIDC_PORT}/callback` (where OIDC_PORT equals whatever you've set
the `OIDC_PORT` environment variable equal to).   

For example, if you set `OIDC_PORT` equal to
`3000` the you must configure your provider to allow callbacks to:
`http://localhost:3000/callback`

<hr>

### OIDC Provider PKCE support. 
Many providers require you to explicitly enable the authorization code with
PKCE.  Auth0 for example requires you to set your application type as: Native or
Single Page Application if you wish to use PKCE. 

<hr>

### Built-in Test Provider 
We've add support to use a built in Test OIDC Provider into the CLI example.
You simply pass the `-use-test-provider` option on the CLI and the Test Provider
will be configured and started on an available localhost port.  The Test
Provider only allows you to login with one user which is `alice` with a password
of `fido`.  This very simple Test Provider option removes the dependency of
creating a test account with a "real" provider, if you just want to run the CLI
and see it work.


