package oidc

import (
	"fmt"

	"github.com/hashicorp/cap/sdk/id"
)

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for an State Id or Nonce
func NewId(optionalPrefix string) (string, error) {
	id, err := id.New(optionalPrefix)
	if err != nil {
		return "", fmt.Errorf("unable to generate id: %w", err)
	}
	return id, nil
}
