# cap CHANGELOG

Canonical reference for changes, improvements, and bugfixes for cap.
## 0.3.3
### Bug fixes:
* LDAP
  * A more compete fix for `escapeValue(...)` and we've stopped exporting it ([**PR**](https://github.com/hashicorp/cap/pull/78))
## 0.3.2

### Bug fixes:
* Address a set of LDAP issues ([**PR**](https://github.com/hashicorp/cap/pull/77)):
  * Properly escape user filters when using UPN domains
  * Increase max tls to 1.3
  * Improve `EscapeValue(...)`
  * Use text template for rendering filters

## 0.3.1

### Bug Fixes
* Fixes integer overflow in `auth_time` claim validation when compiled for 32-bit 
  architecture ([**PR**](https://github.com/hashicorp/cap/pull/76))

## 0.3.0
#### OIDC
* Add `ProviderConfig` which creates a provider that doesn't support
  OIDC discovery. It's probably better to use NewProvider(...) with discovery
  whenever possible ([**PR**](https://github.com/hashicorp/cap/pull/57) and [issue](https://github.com/hashicorp/cap/issues/55)).
* Improve WSL detection ([**PR**](https://github.com/hashicorp/cap/pull/51))
* Add option to allow all of IAT, NBF, and EXP to be missing
  ([**PR**](https://github.com/hashicorp/cap/pull/50))
* Validate sub and aud are present in an id_token ([**PR**](https://github.com/hashicorp/cap/pull/48))

#### LDAP
* Add better (more consistent) timeouts ([**PR**](https://github.com/hashicorp/cap/pull/61))
* Add better error msgs on failed search queries ([**PR**](https://github.com/hashicorp/cap/pull/60))
* Add new config fields for including/excluding user attrs ([**PR**](https://github.com/hashicorp/cap/pull/59))
* Add `WithUserAttributes(...)` option to the ldap package that allows callers
  to request that attributes be returned for the authenticating user ([**PR**](https://github.com/hashicorp/cap/pull/58))



## 0.2.0 (2022/04/08)
* Add support for LDAP/AD authentication ([**PR**](https://github.com/hashicorp/cap/pull/47))
  

## 0.1.1 (2021/06/24)

### Bug Fixes

* oidc: remove extra unused parameter to Info logging in TestProvider.startCachedCodesCleanupTicking
  ([PR](https://github.com/hashicorp/cap/pull/42)).

## 0.1.0 (2021/05/21)

v0.1.0 is the first release.  As a result there are no changes, improvements, or bugfixes from past versions.

