# authcode_spa


An example OIDC SPA (single page application). 

The example uses the `oidc` and `callback` packages to compose a solution. Among
other things, it demonstrates how to configure and use an
`oidc.AuthCodeProvider` to implement a solution. 

It extends `oidc.State` and `oidc.Token` in combination with a State cache to
compose a solution.

It also shows example closures that meet the `callback.SuccessResponseFn` and
`callback.ErrorResponseFn` interfaces and uses the State cache to communicate if
the user successfully authenticated with the OIDC provider.  

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


