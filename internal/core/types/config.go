package types

import (
	"fmt"
	"time"
)

// Output formats supported by the renderers.
const (
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
	FormatText     = "text"
)

// FailOn thresholds accepted by the CLI and the GitHub Action.
const (
	FailOnNever    = "never"
	FailOnCritical = "critical"
	FailOnWarning  = "warning"
)

// Config is the validated configuration of one scan. Construct it through
// DefaultConfig and mutate before calling Validate.
type Config struct {
	Timeout      time.Duration
	MaxRedirects int
	MaxBodyBytes int64
	Format       string
	FailOn       string
	Redact       bool
	Verbose      bool
	UserAgent    string
	// AllowPrivateTargets disables the SSRF blocklist. It exists only for
	// operators scanning their own internal hosts and is never enabled by
	// the API server.
	AllowPrivateTargets bool
	// PageSpeedAPIKey enables optional PageSpeed Insights enrichment. Empty
	// means the check runs on local timing metrics only.
	PageSpeedAPIKey string
}

// DefaultConfig returns the production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:             15000 * time.Millisecond,
		MaxRedirects:        10,
		MaxBodyBytes:        10 << 20,
		Format:              FormatMarkdown,
		FailOn:              FailOnCritical,
		Redact:              true,
		Verbose:             false,
		UserAgent:           "DownOrWhy/dev (+https://github.com/downorwhy/downorwhy)",
		AllowPrivateTargets: false,
	}
}

var (
	validFormats = map[string]struct{}{
		FormatJSON: {}, FormatMarkdown: {}, FormatHTML: {}, FormatText: {},
	}
	validFailOn = map[string]struct{}{
		FailOnNever: {}, FailOnCritical: {}, FailOnWarning: {},
	}
)

// Validate checks the configuration and returns an error wrapping
// ErrInvalidConfig on the first violation.
func (c Config) Validate() error {
	if c.Timeout < 1000*time.Millisecond || c.Timeout > 120000*time.Millisecond {
		return fmt.Errorf("%w: timeout %s outside 1000ms..120000ms", ErrInvalidConfig, c.Timeout)
	}
	if c.MaxRedirects < 0 || c.MaxRedirects > 10 {
		return fmt.Errorf("%w: maxRedirects %d outside 0..10", ErrInvalidConfig, c.MaxRedirects)
	}
	if c.MaxBodyBytes <= 0 || c.MaxBodyBytes > 10<<20 {
		return fmt.Errorf("%w: maxBodyBytes %d outside 1..10485760", ErrInvalidConfig, c.MaxBodyBytes)
	}
	if _, ok := validFormats[c.Format]; !ok {
		return fmt.Errorf("%w: unknown format %q", ErrInvalidConfig, c.Format)
	}
	if _, ok := validFailOn[c.FailOn]; !ok {
		return fmt.Errorf("%w: unknown fail-on value %q", ErrInvalidConfig, c.FailOn)
	}
	if c.UserAgent == "" {
		return fmt.Errorf("%w: user agent must not be empty", ErrInvalidConfig)
	}
	return nil
}

// ShouldFail reports whether a finished report must produce a non-zero exit
// code under this configuration.
func (c Config) ShouldFail(r *Report) bool {
	switch c.FailOn {
	case FailOnWarning:
		return r.HasCritical() || r.HasWarnings()
	case FailOnCritical:
		return r.HasCritical()
	default:
		return false
	}
}
