# Architecture

## Pipeline

    input URL
      -> normalize (internal/core/url/normalize.go)
      -> safety validation (internal/core/url/safeurl.go)
      -> scanner (internal/core/scanner)
           -> checks: dns, tls, http, redirect, header, cdncache, performance, security
      -> scoring (internal/core/scoring)
           -> health score, severity buckets, owner mapping, recommendations, commands
      -> renderer (internal/core/renderers): json | markdown | html | text
      -> exit code

The pipeline is linear and single-pass. No check may call another check; shared
observations (the HTTP response, the DNS answers, the TLS state) are gathered
once in the scanner and passed to checks as an immutable `ScanTarget`.

## Package rules

| Package | May import | Purpose |
| ------- | ---------- | ------- |
| `internal/core/types` | stdlib only | Report and config data model |
| `internal/core/url` | stdlib, `x/net/idna` | Normalisation and SSRF policy |
| `internal/core/network` | stdlib, `miekg/dns`, `core/url`, `core/types` | HTTP, DNS, TLS clients |
| `internal/core/checks` | `core/types`, `core/network`, `core/url` | One file per check |
| `internal/core/scoring` | `core/types` | Pure functions over a report |
| `internal/core/renderers` | `core/types` | Output formatting, no I/O beyond the writer |
| `internal/core/scanner` | all of the above | Orchestration |
| `internal/shared` | stdlib, `zerolog` | Logging, constants, file helpers |
| `cmd/*` | `internal/*` | Thin entrypoints |

`internal/core/scoring` and `internal/core/renderers` must remain free of
network access so they stay trivially testable with golden files.

## Check contract

Every check exposes:

    func Run(ctx context.Context, target ScanTarget, cfg types.Config) types.CheckResult

A check never panics, never returns an error, and never exits the process. A
failed check records `status: "error"` plus an `error` string and the scan
continues. This is what allows a useful report to be produced for a target that
is completely unreachable.

## Concurrency

DNS resolution across the system resolver and the three DoH resolvers runs
concurrently with a shared context deadline. All other checks run sequentially
after the single HTTP transaction, because they read the same response.

## Timeouts

One `context.Context` carries the total scan budget (default 15000 ms). Each
network client derives a sub-budget from it. No client uses a bare
`http.DefaultClient` or a background context.
