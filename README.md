# cap

The `cap` provides a collection of authentication packages related to OIDC, JWKs and Distributed Claims.

* [`oidc`](./oidc): a package for writing OIDC Provider integrations. Primary types provided by the package are: State, Token, Config, Provider. The package also provides callbacks (in the form of http.HandlerFunc) for handling OIDC provider responses to authorization code flow (with optional PKCE) and implict flow authentication attempts.
