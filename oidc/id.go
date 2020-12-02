package oidc

import (
	"fmt"

	"github.com/hashicorp/cap/sdk/id"
)

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for an State Id or Nonce
func NewId(optionalPrefix string) (string, error) {
	const op = "NewId"
	id, err := id.New(optionalPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: unable to generate id: %w", op, err)
	}
	return id, nil
}
