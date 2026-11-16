# `make conform` is the gate: CI runs it and so does a contributor.
SHELL := /bin/bash
export CGO_ENABLED := 0
export GOWORK := off

GOLANGCI := .cache/bin/golangci-lint
GOLDEN_PACKAGES = $$(go list -tags integration -f '{{.ImportPath}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... | awk '{for (i = 2; i <= NF; i++) if ($$i ~ /internal\/golden$$/) {print $$1; next}}')

.PHONY: conform build test integration vet fmt fmt-check tidy tidy-check generate generate-check
.PHONY: cross lint structlint structlint-test vuln upgrade tools golden-update clean

conform: fmt-check vet build test integration tidy-check generate-check cross structlint structlint-test lint

build:
	go build -o bin/slopmop ./cmd/slopmop

test:
	go test -count=1 -shuffle=on -cover ./...

integration:
	go test -count=1 -tags integration ./cmd/...

vet:
	go vet -tags integration ./...

fmt: tools
	$(GOLANGCI) fmt

fmt-check: tools
	@out="$$("$$(go env GOROOT)/bin/gofmt" -l .)" && test -z "$$out" || { echo "$$out"; echo "gofmt: not formatted"; exit 1; }
	$(GOLANGCI) fmt --diff

tidy:
	go mod tidy

tidy-check:
	go mod tidy -diff

generate:
	go generate ./...

# Compares the tree before and after, so uncommitted work does not fail it.
generate-check:
	@before="$$(git status --porcelain; git diff)"; go generate ./...; \
	test "$$before" = "$$(git status --porcelain; git diff)" || { echo "go generate changed the tree"; exit 1; }

cross:
	GOOS=windows GOARCH=amd64 go build ./...
	GOOS=darwin GOARCH=arm64 go build ./...
	GOOS=linux GOARCH=arm64 go build ./...

lint: tools
	$(GOLANGCI) config verify
	$(GOLANGCI) run

structlint:
	scripts/structlint.sh

# The linter's own regression test: the broken tree yields exactly expected.txt.
structlint-test:
	@diff <(scripts/structlint.sh scripts/testdata/structlint/tree 2>&1) scripts/testdata/structlint/expected.txt

# go run ignores the module's Go version, so the toolchain is named.
vuln:
	GOTOOLCHAIN="$$(go env GOVERSION)" go run golang.org/x/vuln/cmd/govulncheck@latest ./...

upgrade:
	scripts/upgrade.sh

tools:
	@scripts/tools.sh

golden-update:
	go test -count=1 -tags integration $(GOLDEN_PACKAGES) -update

clean:
	rm -rf bin .cache
