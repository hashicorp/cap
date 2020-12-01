# authcode_cli


An example OIDC user authentication CLI. 

The example uses the `oidc` and `callback` packages to compose a solution. Among
other things, it demonstrates how to configure and use an
`oidc.Provider` to implement a solution. 

It combines `oidc.State`, `callback.SingleStateReader`, and
the `callback.AuthCodeWithState()` function to compose a "one-time use" oidc
authentication response callback that's tied to the CLI's authentication attempt.  

It also shows example closures that meet the `callback.SuccessResponseFn` and
`callback.ErrorResponseFn` interfaces and uses channels to communicate if the
CLI user successfully authenticated with the OIDC provider. 

<hr>

## Setup
### Require environment variables

* OIDC_CLIENT_ID: Your Relying Party client id.
* OIDC_CLIENT_SECRET: Your Rely Party secret.
* OIDC_ISSUER: The OIDC issuer identifier (aka the discover URL)
* OIDC_PORT: The port you'd like to use for your callback HTTP listener.
### OIDC Provider

You must configure your provider's allowed callbacks to include:
`http://localhost:{OIDC_PORT}/callback` (where OIDC_PORT equals whatever you've set
the `OIDC_PORT` environment variable equal to).   

For example, if you set `OIDC_PORT` equal to
`3000` the you must configure your provider to allow callbacks to: `http://localhost:3000/callback`


