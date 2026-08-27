// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

// ProviderType identifies a given known OIDC provider.
type ProviderType string

const (
	// ProviderTypeAzure is the provider identifier for Microsoft Azure.
	ProviderTypeAzure ProviderType = "azure"
)

// supportedProviderTypes is a map of known OIDC provider types.
var supportedProviderTypes = map[ProviderType]bool{
	ProviderTypeAzure: true,
}

// SupportedProviderType returns true if the given provider type is known and supported.
func SupportedProviderType(p ProviderType) bool {
	return supportedProviderTypes[p]
}
