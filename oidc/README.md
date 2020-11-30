# oidc

oidc is a package for writing OIDC Provider integrations using OIDC flows
(initially only the authorization code has been implemented).  

Primary types provided by the package:

* `State`: represents one OIDC authentication flow for a user.  It contains the
  data needed to uniquely represent that one-time flow across the multiple
  interactions needed to complete the OIDC flow the user is attempting.  All
  States contain an expiration for the user's OIDC flow.

* `Token`: represents an OIDC id_token, as well as an Oauth2 access_token and
  refresh_token (including the the access_token expiry)

* `AuthCodeConfig`: provides the configuration for a typical 3-legged OIDC
  authorization code flow (for example: client Id/Secret, redirectUrl, supported
  signing algorithms, additional scopes requested, etc)

* `AuthCodeProvider`: provides integration with a provider using the typical
  3-legged OIDC authorization code flow. The provider provides capabilities
  like: generating an auth URL, exchanging codes for tokens, verifying tokens,
  making user info requests, etc.

* `Alg`: represents asymmetric signing algorithms

* `Error`: provides an error and provides the ability to specify an error code,
  operation that raised the error, the kind of error, and any wrapped error

#### `oidc.callback`
The callback package includes the ability to create a `http.HandlerFunc` which can be used
for the 3rd leg of the OIDC flow where the authorization code is exchanged for
tokens.   

<hr>

### Examples:

* [CLI example](examples/authcode_cli/) which implements an OIDC
  user authentication CLI.  The example  uses the `oidc` and `callback` packages
  to compose a solution.  

