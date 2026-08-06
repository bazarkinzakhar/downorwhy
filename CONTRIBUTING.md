# Contributing

## Before you open a pull request

    make fmt vet lint test

All four must pass. CI runs the same commands plus `govulncheck`.

## Scope

DownOrWhy is deliberately narrow. Changes that add a browser engine, a
frontend, a database, telemetry, or a language model will be declined. New
checks are welcome if they are read-only, deterministic, and produce a finding
with an owner and a verification command.

## Adding a check

1. Add `internal/core/checks/<name>check.go` exposing
   `func Run(ctx context.Context, target ScanTarget, cfg types.Config) types.CheckResult`.
2. Never return an error and never panic; record `status: "error"` instead.
3. Add table-driven tests with `httptest` or a stub resolver. No live hosts.
4. Document the `evidence` and `details` keys in docs/report-schema.md.
5. Add the owner mapping and any new recommendation text in
   `internal/core/scoring`.

## Commit messages

Conventional Commits, for example `feat(checks): add DNSSEC failure detection`.

## Reporting a vulnerability

Do not open a public issue. Follow SECURITY.md.

## License

Contributions are accepted under Apache-2.0.
