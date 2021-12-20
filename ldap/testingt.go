package ldap

import (
	"errors"

	"github.com/hashicorp/go-hclog"
)

// TestingT defines a very slim interface required by the TestDirectory and any
// test functions it uses.
type TestingT interface {
	Errorf(format string, args ...interface{})
	FailNow()
	Log(...interface{})
}

// CleanupT defines an single function interface for a testing.Cleanup(func()).
type CleanupT interface{ Cleanup(func()) }

// HelperT defines a single function interface for a testing.Helper()
type HelperT interface{ Helper() }

// InfofT defines a single function interface for a Info(format string, args ...interface{})
type InfofT interface {
	Infof(format string, args ...interface{})
}

// TestingLogger defines a logger that will implement the TestingT interface so
// it can be used with StartTestDirectory(...) as its t TestingT parameter.
type TestingLogger struct {
	Logger hclog.Logger
}

// NewTestingLogger makes a new TestingLogger
func NewTestingLogger(logger hclog.Logger) (*TestingLogger, error) {
	if logger == nil {
		return nil, errors.New("missing logger")
	}
	return &TestingLogger{
		Logger: logger,
	}, nil
}

// Errorf will output the error to the log
func (l *TestingLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Error(format, args...)
}

// Infof will output the info to the log
func (l *TestingLogger) Infof(format string, args ...interface{}) {
	l.Logger.Info(format, args...)
}

// FailNow will panic
func (l *TestingLogger) FailNow() {
	panic("testing.T failed, see logs for output (if any)")
}

func (l *TestingLogger) Log(i ...interface{}) {
	l.Logger.StandardLogger(&hclog.StandardLoggerOptions{}).Println(i...)
}
