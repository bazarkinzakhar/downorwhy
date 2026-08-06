// Package shared contains cross-cutting constants and helpers that are not
// tied to a specific check or renderer.
package shared

import "time"

const (
	// Name is the product name used in logs, reports and the User-Agent.
	Name = "DownOrWhy"

	// UserAgentTemplate is formatted with the build version to identify
	// outbound requests. Scanned hosts must be able to recognise the scanner.
	UserAgentTemplate = "DownOrWhy/%s (+https://github.com/downorwhy/downorwhy)"

	// SchemaVersion is the version of the report JSON schema. It follows
	// semantic versioning independently of the binary version.
	SchemaVersion = "1.0.0"
)

const (
	// DefaultTimeout is the total budget for a single scan.
	DefaultTimeout = 15000 * time.Millisecond

	// MaxTimeout is the upper bound accepted from user input.
	MaxTimeout = 120000 * time.Millisecond

	// MinTimeout is the lower bound accepted from user input.
	MinTimeout = 1000 * time.Millisecond

	// MaxRedirects is the hard limit on redirect hops per scan.
	MaxRedirects = 10

	// MaxBodyBytes is the hard limit on downloaded response body size.
	MaxBodyBytes int64 = 10 << 20 // 10 MiB
)

// Version is overridden at build time via -ldflags.
var Version = "dev"
