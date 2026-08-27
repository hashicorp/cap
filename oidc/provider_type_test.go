// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupportedProviderType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		provider ProviderType
		want     bool
	}{
		{
			name:     "supported azure provider",
			provider: ProviderTypeAzure,
			want:     true,
		},
		{
			name:     "empty provider",
			provider: ProviderType(""),
			want:     false,
		},
		{
			name:     "unsupported google provider",
			provider: ProviderType("google"),
			want:     false,
		},
		{
			name:     "unknown provider",
			provider: ProviderType("unknown"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SupportedProviderType(tt.provider)
			require.Equal(t, tt.want, got)
		})
	}
}
