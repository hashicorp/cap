// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

/*
The azure package provides support for resolving Azure Entra ID distributed
group claims. When a user belongs to more than 200 groups, Azure omits the
groups claim from the token and includes an overage indicator pointing to the
Microsoft Graph API instead. For more information on this limitation see
https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#groups-overage-claim

ResolveGroupClaims detects that overage indicator and fetches the full list of
group IDs from the Graph API on behalf of the caller.
*/
package azure
