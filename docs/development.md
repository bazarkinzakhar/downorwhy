# Development

## Requirements

- Go 1.23 or newer
- `golangci-lint` v2
- `gofumpt`
- `govulncheck`

Install the tooling:

    make tools

## Everyday commands

    go mod download
    go vet ./...
    golangci-lint run
    go test ./... -race -cover
    go build ./...
    govulncheck ./...

Or simply:

    make

## Running from source

    go run ./cmd/downorwhy scan https://example.com --format markdown
    go run ./cmd/downorwhy-server --port 8787

## Layout

See docs/architecture.md for the package rules. New checks go in
`internal/core/checks/` as a single file exposing `Run`, plus a matching
`_test.go` using `httptest` or a stub resolver.

## Testing rules

- Table-driven tests for every exported function.
- No test may contact a network host that DownOrWhy does not control, except
  the explicitly documented, opt-in integration tests guarded by
  `-tags=integration`.
- Renderer output is verified with golden files under `test/fixtures/`.
  Regenerate with `make test-golden`, and review the diff before committing.
- Race detector is mandatory in CI.

## Formatting and linting

`gofumpt` is the formatter of record; `goimports` grouping uses the local
prefix `github.com/downorwhy/downorwhy`. CI fails on unformatted files.

## Commits and releases

Conventional Commits. Releases are tag-driven; see .github/workflows/release.yml
and CONTRIBUTING.md.
