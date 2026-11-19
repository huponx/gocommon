GO ?= go

.PHONY: help tidy fmt vet test cover lint check clean

help:
	@printf '%s\n' \
		'tidy     go mod tidy' \
		'fmt      gofmt -w on every package' \
		'vet      go vet ./...' \
		'test     go test ./... (add RACE=1 for the race detector)' \
		'cover    tests with coverage: coverage.out and coverage.html' \
		'lint     golangci-lint run (skipped when it is not installed)' \
		'check    fmt check, vet and test: what the CI runs' \
		'clean    remove coverage files'

tidy:
	$(GO) mod tidy

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
