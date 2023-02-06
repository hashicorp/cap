// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRequest struct {
	*oidc.Req
}

func newTestRequest() *testRequest {
	r, _ := oidc.NewRequest(1*time.Minute, "http://whatever.com")
	return &testRequest{r}
}

func TestSingleRequestReader_Read(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		oidcRequest oidc.Request
		idOverride  string
		wantErr     bool
	}{
		{"valid", newTestRequest(), "", false},
		{"not-found", newTestRequest(), "not-found", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			sr := &SingleRequestReader{
				Request: tt.oidcRequest,
			}
			var state string
			switch {
			case tt.idOverride != "":
				state = tt.idOverride
			default:
				state = sr.Request.State()
			}
			got, err := sr.Read(ctx, state)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, oidc.ErrNotFound))
				return
			}
			require.NoError(err)
			assert.Equal(tt.oidcRequest, got)
		})
	}
}
