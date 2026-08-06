# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Repository foundation: Go module, linter configuration, Makefile.
- Core report data model in `internal/core/types`: `Report`, `Finding`,
  `CheckResult`, `Checks`, `Recommendation`, `Command`.
- Scan configuration with bounded timeout, redirect and body-size limits.
- Typed domain errors with sentinel values and CLI exit-code mapping.
- Product, architecture, report-schema and development documentation.
