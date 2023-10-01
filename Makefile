# Format Go files, ignoring files marked as generated through the header defined at
# https://pkg.go.dev/cmd/go#hdr-Generate_Go_files_by_processing_source
.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go')

.PHONY: gen
gen: fmt copywrite

.PHONY: copywrite
copywrite:
	copywrite headers

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go
	go install github.com/hashicorp/copywrite@v0.15.0