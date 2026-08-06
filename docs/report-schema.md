# Report schema

Schema version: `1.0.0`. The version is embedded in every report as
`schemaVersion` and follows semantic versioning independently of the binary
version. Additive fields are a minor bump; removing or retyping a field is a
major bump.

## Top level

| Field | Type | Notes |
| ----- | ---- | ----- |
| `schemaVersion` | string | e.g. `"1.0.0"` |
| `generatedAt` | string | RFC 3339 UTC |
| `inputUrl` | string | Normalised input, query redacted unless `--no-redact` |
| `finalUrl` | string, optional | Absent when no HTTP response was obtained |
| `reachable` | bool | True when an HTTP response was received |
| `overallStatus` | string | `healthy` \| `degraded` \| `down` \| `error` |
| `healthScore` | int | 0–100 |
| `critical` | Finding[] | Never null |
| `warnings` | Finding[] | Never null |
| `info` | Finding[] | Never null |
| `checks` | Checks | Eight fixed keys |
| `recommendations` | Recommendation[] | Ordered by priority |
| `commands` | Command[] | Shell commands to reproduce findings |

## Finding

| Field | Type | Values |
| ----- | ---- | ------ |
| `severity` | string | `critical` \| `warning` \| `info` |
| `layer` | string | `dns` \| `tls` \| `http` \| `redirect` \| `headers` \| `cdn` \| `cache` \| `performance` \| `security` \| `hosting` |
| `title` | string | One line, readable without context |
| `description` | string | Probable cause and impact |
| `evidence` | object | Check-specific; see per-check tables below |
| `owner` | string | `dns-provider` \| `hosting-provider` \| `devops` \| `backend` \| `frontend` \| `security` \| `user` |

`evidence` is intentionally untyped. Each check documents its keys in this file
as the checks land; consumers must treat unknown keys as additive and must not
fail on them.

## CheckResult

| Field | Type | Notes |
| ----- | ---- | ----- |
| `name` | string | `dns`, `tls`, `http`, `redirects`, `headers`, `cdnCache`, `performance`, `security` |
| `status` | string | `pass` \| `warn` \| `fail` \| `skipped` \| `error` |
| `durationMs` | int | Wall time of the check |
| `summary` | string | One-line result |
| `details` | object | Check-specific measurements |
| `findings` | Finding[] | Same findings also appear in the top-level buckets |
| `error` | string, optional | Present only when `status` is `error` |

## Recommendation

`title`, `description`, `owner`, `priority` (`critical` \| `high` \| `medium`
\| `low`).

## Command

`title`, `command`, `description`. Commands are built only from a validated
host name and a fixed template; no user-controlled string is interpolated
without validation, and commands are never executed by DownOrWhy.

## Stability guarantees

- Arrays are always present, never `null`.
- Enumerations only grow; existing values are not renamed within a major
  schema version.
- `healthScore` is deterministic for identical measurements.
