// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build tools
// +build tools

// This file ensures tool dependencies are kept in sync.  This is the
// recommended way of doing this according to
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// To install the following tools at the version used by this repo run:
// $ make tools
// or
// $ go generate -tags tools tools/tools.go

package tools

// NOTE: This must not be indented, so to stop goimports from trying to be
// helpful, it's separated out from the import block below. Please try to keep
// them in the same order.
//go:generate go install mvdan.cc/gofumpt

import (
	_ "mvdan.cc/gofumpt"
)
