# DownOrWhy

DownOrWhy explains why a website is down, slow, blocked, or misconfigured.

Give it a public URL. It returns an engineering report that states whether the
site is reachable, what is broken or risky, the probable root cause, the
affected layer (DNS, TLS, HTTP, CDN, cache, performance, security, hosting),
who is expected to fix it, and the exact commands to verify the problem
yourself.

Terminal-first. No frontend, no SPA, no browser engine, no JavaScript
execution, no language model. Reports are static JSON, Markdown, HTML or
plain text.

## Status

Under active development. See CHANGELOG.md for what is implemented.

## Install

    go install github.com/downorwhy/downorwhy/cmd/downorwhy@latest

## Use

    downorwhy https://example.com
    downorwhy scan https://example.com --format json
    downorwhy scan https://example.com --format html --output report.html
    downorwhy scan https://example.com --fail-on critical

Markdown is the default when stdout is a terminal; JSON otherwise, so the tool
composes with `jq` and CI pipelines without extra flags.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Scan completed, no critical findings |
| 1 | Scan completed, critical findings present |
| 2 | Invalid input or unsafe target |
| 3 | Internal error |
| 4 | Target unreachable or timed out; report still produced |

## Safety

DownOrWhy is a network scanner and is built to be safe to run from CI and from
a server. It refuses loopback, private, link-local, unique-local, multicast and
reserved addresses, and cloud metadata endpoints, both for the input URL and
for every redirect hop and every resolved IP. Bodies are capped at 10 MiB,
redirects at 10 hops, and query strings are redacted in reports by default.
See docs/security.md.

## Documentation

- docs/product.md — what the product does and for whom
- docs/architecture.md — package layout and scan pipeline
- docs/report-schema.md — report JSON schema
- docs/cli.md — CLI reference
- docs/github-action.md — GitHub Action usage
- docs/api-server.md — local API server
- docs/security.md — security controls
- docs/threat-model.md — threat model
- docs/compliance-controls.md — control mapping for audit preparation
- docs/development.md — building, testing, contributing

## License

Apache-2.0. See LICENSE.
