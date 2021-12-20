
.PHONY: test
test:
	find . -name go.mod -execdir go test -count=1 ./... \;

.PHONY: build
build:
	find . -name go.mod -execdir go build ./... \;


.PHONY: test-race
test-race:
	# TODO: we need an upstream PR to resolve a race in the
	# github.com/vjeantet/ldapserver 
	go test -race -count=1 