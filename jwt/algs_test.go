// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupportedSigningAlgorithm(t *testing.T) {
	type args struct {
		algs []Alg
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "supported signing algorithms",
			args: args{
				algs: []Alg{RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, EdDSA},
			},
		},
		{
			name: "unsupported signing algorithm none",
			args: args{
				algs: []Alg{Alg("none")},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SupportedSigningAlgorithm(tt.args.algs...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
