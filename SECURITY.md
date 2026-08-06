# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue and do not disclose
details until a fix is released.

Include: affected version or commit, reproduction steps, and the impact you
believe the issue has. We acknowledge reports within 3 business days, provide
an assessment within 10 business days, and aim to ship a fix for confirmed
high-severity issues within 30 days. We will credit reporters who want it.

## Supported versions

The latest released minor version receives security fixes. Pre-1.0, only the
most recent tag is supported.

## Security properties of this tool

DownOrWhy makes outbound network requests to a target you supply. It is
designed to be safe to run from CI and from a server:

- The input URL, every resolved IP address and every redirect hop are checked
  against a deny list covering loopback, private, link-local, unique-local,
  multicast and reserved ranges, and cloud metadata endpoints.
- Redirects are capped at 10 hops, response bodies at 10 MiB, and the whole
  scan at a bounded timeout.
- No JavaScript is executed and no page is rendered.
- Query strings are redacted in reports by default.
- No telemetry, no analytics and no outbound reporting of scan results.

Details and the control mapping are in docs/security.md,
docs/threat-model.md and docs/compliance-controls.md. Those documents describe
implemented security controls; they are not, and do not claim to be, any form
of certification.

## Out of scope

- Findings produced by scanning a third-party site are that site's issue, not
  ours.
- Using DownOrWhy against systems you are not authorised to test.
