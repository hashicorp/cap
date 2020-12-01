/*
oidc is a package for writing OIDC Provider integrations using OIDC flows

Primary types provided by the package

* State: represents one OIDC authentication flow for a user.  It contains the
data needed to uniquely represent that one-time flow across the multiple
interactions needed to complete the OIDC flow the user is attempting.  All
States contain an expiration for the user's OIDC flow.

* Token: represents an OIDC id_token, as well as an Oauth2 access_token and
refresh_token (including the the access_token expiry)

* Config: provides the configuration for a typical 3-legged OIDC
authorization code flow (for example: client Id/Secret, redirectUrl, supported
signing algorithms, additional scopes requested, etc)

* Provider: provides integration with a provider using the typical
3-legged OIDC authorization code flow. The provider provides capabilities
like: generating an auth URL, exchanging codes for tokens, verifying tokens,
making user info requests, etc.

* Alg: represents asymmetric signing algorithms

The oidc.callback package

The callback package includes the ability to create a http.HandlerFunc which can be used
for the 3rd leg of the OIDC flow where the authorization code is exchanged for
tokens.

Examples

* OIDC authentication CLI:
https://github.com/hashicorp/cap/tree/jimlambrt-initial/oidc/examples/authcode_cli/



* OIDC authentication SPA:
https://github.com/hashicorp/cap/tree/jimlambrt-initial/oidc/examples/authcode_cli/


*/
package oidc
