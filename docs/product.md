# Product

## Problem

When a site is down or slow, the first hour is spent arguing about whose
problem it is. The DNS provider blames the host, the host blames the app team,
and the person who noticed the outage has no vocabulary to describe what they
saw. Existing tools return raw data — dig output, curl timings, header dumps —
and leave interpretation to the reader.

## What DownOrWhy does

DownOrWhy performs a fixed set of read-only checks against a public URL and
converts the raw observations into three things a raw dump does not provide:

1. A probable cause, stated in a sentence.
2. An owner: which team or provider can actually fix it.
3. A verification command the reader can paste into a shell.

## Audiences and what each one reads

| Reader | Reads |
| ------ | ----- |
| Non-technical site owner | Overall status, health score, plain-language finding titles |
| Support agent | Findings and owners, to route the ticket correctly |
| Frontend engineer | Headers, cache, performance, mixed content |
| Backend engineer | HTTP status, TTFB, redirects, cookies |
| DevOps / SRE | DNS, TLS, CDN, IPv4/IPv6 asymmetry, timings |
| Security engineer | Security headers, TLS posture, cookie flags, exposure indicators |

## Non-goals

- No browser rendering, no JavaScript execution, no screenshots.
- No authenticated scanning, no crawling, no vulnerability exploitation.
- No stored history, no accounts, no database in v1.
- No telemetry and no analytics, by default or otherwise.
- No language model anywhere in the pipeline. Every sentence in a report comes
  from deterministic rules over measured values.

## Delivery surfaces

- `downorwhy` CLI (single static binary)
- Docker-based GitHub Action, writing a job summary
- `downorwhy-server`, a stateless local HTTP API with no UI
- Static HTML / Markdown / JSON report artefacts
