# spa


An example OIDC SPA (single page application) that supports both the authorization
code (with optional PKCE) and implicit OIDC flows.

The example uses the `oidc` and `callback` packages to compose a solution. Among
other things, it demonstrates how to configure and use an
`oidc.Provider` to implement a solution. 

It extends `oidc.State` and `oidc.Token` in combination with a State cache to
compose a solution.

It also shows example closures that meet the `callback.SuccessResponseFn` and
`callback.ErrorResponseFn` interfaces and uses the State cache to communicate if
the user successfully authenticated with the OIDC provider.  

<hr>

## Setup
### Require environment variables

* OIDC_CLIENT_ID: Your Relying Party client id.
* OIDC_CLIENT_SECRET: Your Rely Party secret (this is not required for implicit
  flows or authorization code with PKCE flows)
* OIDC_ISSUER: The OIDC issuer identifier (aka the discover URL)
* OIDC_PORT: The port you'd like to use for your callback HTTP listener.

<hr>

### OIDC Provider

You must configure your provider's allowed callbacks to include:
`http://localhost:{OIDC_PORT}/callback` (where OIDC_PORT equals whatever you've set
the `OIDC_PORT` environment variable equal to).   

For example, if you set `OIDC_PORT` equal to
`3000` the you must configure your provider to allow callbacks to: `http://localhost:3000/callback`


<hr>

### OIDC Provider PKCE support. 
Many providers require you to explicitly enable the authorization code with
PKCE.  Auth0 for example requires you to set your application type as: Native or
Single Page Application if you wish to use PKCE. 