package oidc

import (
	"testing"
)

func TestApplyOpts(t *testing.T) {
	// ApplyOpts testing is covered by other tests but we do have just more
	// more test to add here.
	// Let's make sure we don't panic on nil options
	anonymousOpts := struct {
		Names []string
	}{
		nil,
	}
	ApplyOpts(anonymousOpts, nil)
}
