package id

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
)

// NewId generates a ID with an optional prefix.
func New(optionalPrefix string) (string, error) {
	id, err := base62.Random(10)
	if err != nil {
		return "", fmt.Errorf("unable to generate id: %w", err)
	}
	switch {
	case optionalPrefix != "":
		return fmt.Sprintf("%s_%s", optionalPrefix, id), nil
	default:
		return id, nil
	}
}
