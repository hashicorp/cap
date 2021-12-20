package ldap_test

import (
	"bytes"
	"testing"

	"github.com/hashicorp/cap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestingLogger(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	_, err := ldap.NewTestingLogger(nil)
	require.Error(err)

	var buf bytes.Buffer
	l, err := ldap.NewTestingLogger(hclog.New(&hclog.LoggerOptions{
		Output: &buf,
	}))
	require.NoError(err)

	l.Errorf("output", "err", "error")
	assert.Contains(buf.String(), "[ERROR] output: err=error")
	buf.Reset()

	l.Infof("output", "info", "info")
	assert.Contains(buf.String(), "[INFO]  output: info=info")
	buf.Reset()

	l.Log("output", "info", "info")
	assert.Contains(buf.String(), "[INFO]  output info info")
	buf.Reset()

	assert.Panics(func() { l.FailNow() }, "testing.T failed, see logs for output (if any)")
}
