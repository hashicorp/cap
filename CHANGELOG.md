# cap CHANGELOG

Canonical reference for changes, improvements, and bugfixes for cap.

## Next

* Add `WithUserAttributes(...)` option to the ldap package that allows callers
  to request that attributes be returned for the authenticating user ([PR](https://github.com/hashicorp/cap/pull/58))
* Add `ProviderConfig` which creates a provider that doesn't support
  OIDC discovery. It's probably better to use NewProvider(...) with discovery
  whenever possible ([PR](https://github.com/hashicorp/cap/pull/57) and [issue](https://github.com/hashicorp/cap/issues/55)).
* Add Validator `ValidateAllowMissingIatNbfExp` method to allow all of
  iat/nbf/exp to be missing. 

## 0.1.1 (2021/06/24)

### Bug Fixes

* oidc: remove extra unused parameter to Info logging in TestProvider.startCachedCodesCleanupTicking
  ([PR](https://github.com/hashicorp/cap/pull/42)).

## 0.1.0 (2021/05/21)

v0.1.0 is the first release.  As a result there are no changes, improvements, or bugfixes from past versions.

