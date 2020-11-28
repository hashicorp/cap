# authcode_cli


An example OIDC user authentication CLI. 

The example uses the `oidc` and `callback` packages to compose a solution.

Demonstrating how you can combine an `oidc.State`, a `callback.SingleStateReader`,
and the `callback.AuthCodeWithState()` function to build a "one-time use" oidc
authentication response callback that's tied to a specific user's authentication attempt.  

It also shows how to use closures that meet the `callback.SuccessResponseFn` and
`callback.ErrorResponseFn` interfaces to communicate whether or not the user's
authentication succeeded from the callback using a channel and logging any
callback errors.