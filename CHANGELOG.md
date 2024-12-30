# cap CHANGELOG

Canonical reference for changes, improvements, and bugfixes for cap.

## Next

* feat (oidc): add WithVerifier ([PR #141](https://github.com/hashicorp/cap/pull/141))
* feat (ldap): add an option to enable sAMAccountname logins when upndomain is set ([PR #146](https://github.com/hashicorp/cap/pull/146))
* feat (saml): enhancing signature validation in SAML Response ([PR #144](https://github.com/hashicorp/cap/pull/144))
* chore: update dependencies in pkgs: cap, cap/ldap, cap/saml ([PR
  #147](https://github.com/hashicorp/cap/pull/147), [PR
  #148](https://github.com/hashicorp/cap/pull/148), [PR
  #149](https://github.com/hashicorp/cap/pull/149))
* chore: update CODEOWNERS ([PR
  #142](https://github.com/hashicorp/cap/pull/142),[PR
  #143](https://github.com/hashicorp/cap/pull/143) )

## 0.7.0

* Add ability to the SAML test provider to create signed SAML responses by
  @hcjulz ([PR: 135](https://github.com/hashicorp/cap/pull/135))
* Bump golang.org/x/net from 0.22.0 to 0.23.0 by @dependabot ([PR #136](https://github.com/hashicorp/cap/pull/136))
* feat (config): add support for a http.RoundTripper by @jimlambrt ([PR #137](https://github.com/hashicorp/cap/pull/137))
* chore: update deps by @jimlambrt ([PR #138](https://github.com/hashicorp/cap/pull/138))

## 0.6.0

* Add case insensitive user attribute keys configs for LDAP by @jasonodonnell in https://github.com/hashicorp/cap/pull/132
* chore (oidc, jwt, ldap): update deps by @jimlambrt in **https**://github.com/hashicorp/cap/pull/133
* Add empty anonymous group search configs by @jasonodonnell in https://github.com/hashicorp/cap/pull/134

## 0.5.0

### Improvements

* JWT
  * Adds ability to specify more than one `KeySet` used for token validation (https://github.com/hashicorp/cap/pull/128)

## 0.4.1

### Bug fixes

* SAML
  * Truncate issue instant to microseconds to support Microsoft Entra ID enterprise applications (https://github.com/hashicorp/cap/pull/126)

## 0.4.0

### Features

* SAML 
  * Adds support for SAML authentication (https://github.com/hashicorp/cap/pull/99).

### Improvements

* LDAP
  * Add worker pool for LDAP token group lookups ([**PR**](https://github.com/hashicorp/cap/pull/98))

## 0.3.4

### Bug fixes

* OIDC/examples/cli
  * Use free port if OIDC_PORT is not set for the example ([**PR**](https://github.com/hashicorp/cap/pull/79))


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

