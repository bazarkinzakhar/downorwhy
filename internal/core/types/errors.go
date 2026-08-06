package types

import (
	"errors"
	"fmt"
)

// Sentinel errors. Callers must match with errors.Is, never by string.
var (
	// ErrInvalidConfig marks a rejected scan configuration.
	ErrInvalidConfig = errors.New("invalid scan configuration")
	// ErrInvalidURL marks input that is not a usable absolute HTTP(S) URL.
	ErrInvalidURL = errors.New("invalid url")
	// ErrUnsafeTarget marks a target blocked by the SSRF policy.
	ErrUnsafeTarget = errors.New("unsafe target")
	// ErrTooManyRedirects marks a redirect chain exceeding the limit.
	ErrTooManyRedirects = errors.New("too many redirects")
	// ErrBodyTooLarge marks a response body above the configured limit.
	ErrBodyTooLarge = errors.New("response body too large")
	// ErrTimeout marks an operation that exceeded its deadline.
	ErrTimeout = errors.New("operation timed out")
	// ErrUnreachable marks a target that could not be contacted at all.
	ErrUnreachable = errors.New("target unreachable")
	// ErrInternal marks a defect in DownOrWhy itself.
	ErrInternal = errors.New("internal error")
)

// ExitCode values returned by the CLI, as documented in docs/cli.md.
const (
	ExitOK          = 0
	ExitCritical    = 1
	ExitInvalidUse  = 2
	ExitInternal    = 3
	ExitUnreachable = 4
)

// ScanError is a domain error carrying the layer where it occurred and the
// exit code the CLI should use.
type ScanError struct {
	Layer    string
	Op       string
	ExitCode int
	Err      error
}

// Error implements error.
func (e *ScanError) Error() string {
	if e.Layer == "" {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s/%s: %v", e.Layer, e.Op, e.Err)
}

// Unwrap exposes the wrapped sentinel for errors.Is.
func (e *ScanError) Unwrap() error { return e.Err }

// NewScanError builds a ScanError with the exit code implied by err.
func NewScanError(layer, op string, err error) *ScanError {
	return &ScanError{Layer: layer, Op: op, ExitCode: exitCodeFor(err), Err: err}
}

func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, ErrInvalidURL),
		errors.Is(err, ErrUnsafeTarget),
		errors.Is(err, ErrInvalidConfig):
		return ExitInvalidUse
	case errors.Is(err, ErrTimeout),
		errors.Is(err, ErrUnreachable):
		return ExitUnreachable
	default:
		return ExitInternal
	}
}

// ExitCodeOf returns the CLI exit code for err, defaulting to ExitInternal.
func ExitCodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var se *ScanError
	if errors.As(err, &se) {
		return se.ExitCode
	}
	return exitCodeFor(err)
}
