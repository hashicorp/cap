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

type testState struct {
	*oidc.St
}

func newTestState() *testState {
	s, _ := oidc.NewState(1*time.Minute, "http://whatever.com")
	return &testState{s}
}

func TestSingleStateReader_Read(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		state      oidc.State
		idOverride string
		wantErr    bool
	}{
		{"valid", newTestState(), "", false},
		{"not-found", newTestState(), "not-found", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s := &SingleStateReader{
				State: tt.state,
			}
			var id string
			switch {
			case tt.idOverride != "":
				id = tt.idOverride
			default:
				id = s.State.ID()
			}
			got, err := s.Read(ctx, id)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, oidc.ErrNotFound))
				return
			}
			require.NoError(err)
			assert.Equal(tt.state, got)
		})
	}
}
