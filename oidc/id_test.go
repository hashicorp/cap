// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		opt        []Option
		wantErr    bool
		wantPrefix string
		wantLen    int
	}{
		{
			name:    "no-prefix",
			wantLen: DefaultIDLength,
		},
		{
			name:       "with-prefix",
			opt:        []Option{WithPrefix("alice")},
			wantPrefix: "alice",
			wantLen:    DefaultIDLength + len("alice_"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewID(tt.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantPrefix != "" {
				assert.Containsf(got, tt.wantPrefix, "NewID() = %v and wanted prefix %s", got, tt.wantPrefix)
			}
			assert.Equalf(tt.wantLen, len(got), "NewID() = %v, with len of %d and wanted len of %v", got, len(got), tt.wantLen)
		})
	}
}

func Test_WithPrefix(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getIDOpts(WithPrefix("alice"))
	testOpts := idDefaults()
	testOpts.withPrefix = "alice"
	assert.Equal(opts, testOpts)
}
