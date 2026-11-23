GO ?= go

.PHONY: help tidy upgrade outdated fmt vet test cover lint check clean

help:
	@printf '%s\n' \
		'tidy     go mod tidy' \
		'upgrade  upgrade the dependencies (PATCH=1: patch releases only), tidy, build and test' \
		'outdated  list the dependencies that have a newer version' \
		'fmt      gofmt -w on every package' \
		'vet      go vet ./...' \
		'test     go test ./... (add RACE=1 for the race detector)' \
		'cover    tests with coverage: coverage.out and coverage.html' \
		'lint     golangci-lint run (skipped when it is not installed)' \
		'check    fmt check, vet and test: what the CI runs' \
		'clean    remove coverage files'

tidy:
	$(GO) mod tidy

# Upgrade the dependencies to their latest minor/patch releases (PATCH=1: patch releases only), then tidy and
# check that everything still builds and passes. GOWORK=off: resolves against the module proxy, not the sibling
# folders of go.work. Review `git diff go.mod go.sum` before committing.
PATCH ?=
upgrade:
	GOWORK=off $(GO) get -u$(if $(PATCH),=patch) ./...
	GOWORK=off $(GO) mod tidy
	GOWORK=off $(GO) build ./...
	GOWORK=off $(GO) test ./...

# Lists the modules that have a newer version (nothing is changed).
outdated:
	@GOWORK=off $(GO) list -u -m -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

RACE ?=
test:
	$(GO) test $(if $(RACE),-race) ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo 'golangci-lint is not installed, skipped'

# fails when a file is not gofmt-ed
check: vet test
	@test -z "$$(gofmt -l .)" || { echo 'gofmt needed on:'; gofmt -l .; exit 1; }

clean:
	rm -f coverage.out coverage.html
