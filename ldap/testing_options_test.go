package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_WithTestDefaults(t *testing.T) {

	tests := []struct {
		name     string
		defaults *TestDefaults
		want     *TestDefaults
	}{
		{
			name: "empty",
			want: testDefaults(t).withDefaults,
		},
		{
			name: "UserAttr",
			defaults: &TestDefaults{
				UserAttr: "userattr",
			},
			want: func() *TestDefaults { d := testDefaults(t).withDefaults; d.UserAttr = "userattr"; return d }(),
		},
		{
			name: "GroupAttr",
			defaults: &TestDefaults{
				GroupAttr: "groupattr",
			},
			want: func() *TestDefaults { d := testDefaults(t).withDefaults; d.GroupAttr = "groupattr"; return d }(),
		},
		{
			name: "UserDN",
			defaults: &TestDefaults{
				UserDN: "userdn",
			},
			want: func() *TestDefaults { d := testDefaults(t).withDefaults; d.UserDN = "userdn"; return d }(),
		},
		{
			name: "GroupDN",
			defaults: &TestDefaults{
				GroupDN: "groupdn",
			},
			want: func() *TestDefaults { d := testDefaults(t).withDefaults; d.GroupDN = "groupdn"; return d }(),
		},
		{
			name: "UPNDomain",
			defaults: &TestDefaults{
				UPNDomain: "upndomain",
			},
			want: func() *TestDefaults { d := testDefaults(t).withDefaults; d.UPNDomain = "upndomain"; return d }(),
		},
	}
	for _, tc := range tests {
		assert := assert.New(t)
		o := WithTestDefaults(t, tc.defaults)
		opts := getTestOpts(t, o)
		assert.Equal(tc.want, opts.withDefaults)
	}
}
