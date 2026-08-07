# downorwhy

A website diagnostics CLI tool. It accepts a URL, performs a set of checks (DNS, TLS, HTTP, redirects, headers, caching, performance, security, IPv4/IPv6), and returns a structured report indicating what is not working or working incorrectly, at which layer the issue occurred, who is responsible for it, and what commands can be used to check it independently.

Single-binary application. Requires no configuration. Has no runtime external dependencies. Uses no browser, JS engine, or language models. Collects no telemetry.

```bash
downorwhy https://example.com

```

---

## Purpose

Diagnosing website issues typically requires sequentially checking multiple independent systems: DNS, TLS certificate, response headers, CDN behavior, network timings. `downorwhy` performs all these checks in a single request and generates a unified report broken down by severity and responsible party (DNS provider, hosting, DevOps, backend, frontend, security).

## Audience and Report Purpose

The report is generated as a single document, but is structured so that different specialists use different parts of it:

| Role | Data Used |
| --- | --- |
| Site Owner | Overall status and health score (0–100) in text format |
| Support | List of findings with responsible party labels — routing tickets without involving engineers |
| Frontend Engineer | Headers, caching, performance metrics, mixed content |
| Backend Engineer | HTTP status, TTFB, redirect chain, cookie attributes |
| DevOps/SRE | DNS resolution results (4 resolvers), TLS certificate chain, CDN cache status, IPv4/IPv6 asymmetry, request phase timings |
| Security Engineer | Security headers (HSTS, CSP), TLS state, cookie attributes, CORS configuration, server information disclosure |

## Scope of Checks

9 checks are implemented. Each is a pure function operating on a single set of observations (a single HTTP request and a single set of DNS responses for the entire pipeline; no repeated network calls are made).

* **DNS** — system resolver and DoH requests to Cloudflare, Google, Quad9; A/AAAA records, CNAME chains, latency per resolver, discrepancies between resolvers, DNSSEC AD bit, NXDOMAIN/SERVFAIL/timeout detection.
* **TLS** — manual TLS handshake with independent validation: certificate expiration, hostname matching, self-signed certificate detection, trust chain verification against system root certificates, negotiated protocol version, cipher suite, TLS 1.0 availability check.
* **HTTP** — status code classification (5xx — critical, 4xx — warning, 3xx — informational), protocol used (HTTP/1.1 or h2), compression presence, response body truncation indicator.
* **Redirects** — cycle detection, HTTPS-to-HTTP downgrade, transition between www and non-www, insecure destination address (private IP, cloud metadata), invalid Location header.
* **Headers** — presence of HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy; CORS wildcard conflict with credentials; Set-Cookie attributes (Secure, HttpOnly, SameSite).
* **CDN/Caching** — CF-Cache-Status, generalized X-Cache, Cache-Control conflicts (no-store, private, public combined with Set-Cookie), Age, ETag, Last-Modified, Vary values.
* **Performance** — TTFB (warning at >1500 ms, critical at >3000 ms), total time (thresholds 10000/20000 ms), response body size (5/15 MB), DNS and TLS handshake timings, approximate bandwidth. All metrics are collected locally via `net/http/httptrace`. Optional PageSpeed Insights integration via an environment variable API key.
* **Security** — server data disclosure via Server, X-Powered-By, X-AspNet-Version headers; count of mixed-content links in HTML body; signs of open directory listing; resolved IP address ownership check.
* **IPv4/IPv6** — presence of A and AAAA records, address family of the actually established connection.

## Report Generation

Each check returns a status (`pass`, `warn`, `fail`, `skipped`), execution duration, text summary, key-value set, and a list of findings. A check does not interrupt pipeline execution or crash the process — on internal error, the result is assigned an `error` status, and processing continues. The report is always generated, including cases of complete target unavailability.

The health score (`healthScore`) is calculated using a deterministic formula: `fail` deducts 25 points, `warn` deducts 10 points; `skipped` and `error` statuses incur no penalty. The final range determines the status: `≥85` — healthy, `≥50` — degraded, `<50` — down.

Each finding contains: severity level, layer (dns/tls/http/...), header, description of the probable cause, evidence (data from the specific check), and a responsible party label (dns-provider, hosting-provider, devops, backend, frontend, security, user). Additionally, prioritized recommendations and a list of shell commands for self-verification of the specified issue are generated.

Example JSON report structure:

```json
{
  "overallStatus": "degraded",
  "healthScore": 62,
  "reachable": true,
  "finalUrl": "https://example.com/",
  "checks": { "dns": {}, "tls": {}, "http": {} },
  "findings": {
    "critical": [],
    "warnings": [
      {
        "layer": "security",
        "title": "Missing HSTS header",
        "description": "The site does not force the use of HTTPS for subsequent requests.",
        "owner": "security",
        "evidence": { "header": "Strict-Transport-Security", "present": false }
      }
    ],
    "info": []
  },
  "recommendations": [
    { "title": "Add HSTS", "owner": "Security Team", "priority": "high" }
  ],
  "commands": [
    { "title": "Check HSTS header", "command": "curl -sI https://example.com | grep -i strict-transport" }
  ]
}

```

## Installation

```bash
# via Go toolchain
go install github.com/downorwhy/downorwhy/cmd/downorwhy@latest

# prebuilt binaries: linux/darwin/windows, amd64/arm64
# available in GitHub Releases (static binary, ~15 MB)

# Docker
docker run ghcr.io/downorwhy/downorwhy scan https://example.com

```

## Usage

```bash
downorwhy https://example.com                         # report in Markdown
downorwhy -s https://example.com                     # concise output, one line per finding
downorwhy scan https://example.com --format json
downorwhy scan https://example.com --format html -o report.html
downorwhy scan https://example.com --fail-on warning
downorwhy scan https://example.com --timeout 30000
downorwhy scan https://example.com --no-redact

```

By default, the output format is Markdown if stdout is a terminal, and JSON when redirecting output. Exit codes: `0` — no critical findings, `1` — issues found at the specified threshold, `2` — invalid or unsafe URL, `3` — internal error, `4` — target unreachable (report is still generated).

### GitHub Action

```yaml
- uses: downorwhy/downorwhy-action@v1
  with:
    url: https://example.com
    format: markdown
    fail-on: critical
    output: report.md

```

The action is based on a Docker image, adds a job summary, and exits with code 1 if the specified criticality threshold is exceeded.

### API Server

```
POST /v1/scan  {"url": "https://example.com"}  →  JSON report
GET  /healthz                                  →  {"status": "ok"}

```

Stateless, database-free. Unsafe targets are rejected with code 422.

## SSRF Protection

For each established connection, the address is checked against a list of forbidden ranges: loopback, private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`), link-local, unique-local, multicast, unspecified, reserved/documentation/benchmark ranges, as well as known cloud provider metadata endpoints (AWS, GCP, Azure, Alibaba Cloud, Oracle Cloud, DigitalOcean, OpenStack) and the well-known NAT64 prefix. IPv4-mapped IPv6 addresses are normalized before checking.

Additional restrictions: redirect limit — 10, response body size limit — 10 MiB, default timeout — 15 seconds (configurable). Query parameters in the report are redacted by default. Telemetry and analytics collection is not performed.

## Positioning

Difference from `curl`/`wget`: the tool does not simply perform a request, but classifies the result, points out the probable cause and responsible party, and suggests verification commands.

Difference from online scanners (SSL Labs, SecurityHeaders, PageSpeed Insights): execution happens locally, data is not transmitted to third-party servers, and internal address diagnostics are supported when using the `--allow-private` flag.

Difference from monitoring systems (Pingdom, UptimeRobot): the tool is intended for one-off diagnostics on demand rather than continuous monitoring; it stores no history and does not perform periodic checks.

Report wording is generated by deterministic rules based on measured values, without using generative models — which eliminates the risk of incorrect interpretations and requires no calls to external APIs.

## Technical Implementation Details

* Go 1.23+, predominantly standard library: `net/http`, `crypto/tls`, `net/netip`, `crypto/x509`, `net/http/httptrace`, `context`, `embed`, `html/template`, `encoding/json`.
* External dependencies: `cobra` (CLI), `chi` (HTTP router), `miekg/dns` (DoH implementation), `zerolog` (structured logging), `golang.org/x/term` (TTY detection), `golang.org/x/net/idna` (internationalized domain handling), `go-githubactions` (GitHub Action SDK), `testify` (used in tests only).
* SSRF protection is implemented via `netip.Prefix.Contains` without using third-party CIDR manipulation libraries.
* DoH requests are implemented in binary wire format according to RFC 8484 (`application/dns-message`), rather than via an intermediate JSON API.
* TLS verification is performed manually: a connection is established with `InsecureSkipVerify`, after which expiration date, hostname match, trust chain, and self-signed status are checked separately. This approach allows obtaining a set of specific findings instead of a single uninformative verification error.
* The HTTP client manages redirect processing in its own loop (using `http.ErrUseLastResponse`), providing full control over recording each transition and verifying destination address security at every step.
* A custom `Dialer` is implemented to measure DNS resolution and TCP connection setup timings independently, since standard `httptrace` hooks are not called when overriding `DialContext`.
* All network components (resolver, dialer, HTTP transport) are accepted as interfaces via dependency injection, allowing logic to be tested without accessing real network resources.

## Distribution

* GitHub Releases — built via `goreleaser`, multi-platform binaries, SBOM.
* Docker image — `ghcr.io/downorwhy/downorwhy`.
* Installation via `go install`.
* GitHub Actions Marketplace — `downorwhy-action`.

## LICENSE

[APACHE](https://www.apache.org/licenses/LICENSE-2.0.txt)
