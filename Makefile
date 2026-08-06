BINARY      := downorwhy
MODULE      := github.com/downorwhy/downorwhy
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X $(MODULE)/internal/shared.Version=$(VERSION)
GO          ?= go

.PHONY: all
all: tidy fmt vet lint test build

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: fmt
fmt:
	gofumpt -l -w .

.PHONY: fmt-check
fmt-check:
	@out="$$(gofumpt -l .)"; if [ -n "$$out" ]; then echo "gofumpt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	$(GO) test ./... -race -cover

.PHONY: test-golden
test-golden:
	$(GO) test ./internal/core/renderers/... -update

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/downorwhy

.PHONY: vuln
vuln:
	govulncheck ./...

.PHONY: tools
tools:
	$(GO) install mvdan.cc/gofumpt@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

.PHONY: clean
clean:
	rm -rf bin dist
