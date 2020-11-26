package oidc

import "github.com/hashicorp/cap/sdk/id"

// NewId generates a ID with an optional prefix.   The ID generated is suitable
// for an State Id or Nonce
func NewId(optionalPrefix string) (string, error) {
	id, err := id.New(optionalPrefix)
	if err != nil {
		return "", NewError(ErrIdGeneratorFailed, WithOp("oidc.NewId"), WithKind(ErrInternal), WithMsg("unable to generate id"), WithWrap(err))
	}
	return id, nil
}
