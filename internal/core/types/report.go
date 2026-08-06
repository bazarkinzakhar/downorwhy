// Package types defines the wire format of a DownOrWhy report and the
// configuration accepted by the scanner. Everything in this package is pure
// data plus validation; it performs no I/O.
package types

// Severity levels used by findings.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Layer values identify which part of the delivery path a finding belongs to.
const (
	LayerDNS         = "dns"
	LayerTLS         = "tls"
	LayerHTTP        = "http"
	LayerRedirect    = "redirect"
	LayerHeaders     = "headers"
	LayerCDN         = "cdn"
	LayerCache       = "cache"
	LayerPerformance = "performance"
	LayerSecurity    = "security"
	LayerHosting     = "hosting"
)

// Owner values identify who is expected to act on a finding.
const (
	OwnerDNSProvider     = "dns-provider"
	OwnerHostingProvider = "hosting-provider"
	OwnerDevOps          = "devops"
	OwnerBackend         = "backend"
	OwnerFrontend        = "frontend"
	OwnerSecurity        = "security"
	OwnerUser            = "user"
)

// Overall status values for a report.
const (
	StatusHealthy  = "healthy"
	StatusDegraded = "degraded"
	StatusDown     = "down"
	StatusError    = "error"
)

// Priority values for recommendations.
const (
	PriorityCritical = "critical"
	PriorityHigh     = "high"
	PriorityMedium   = "medium"
	PriorityLow      = "low"
)

// Report is the complete result of a single scan. It is the only structure
// that renderers and the HTTP API are allowed to expose.
type Report struct {
	SchemaVersion   string           `json:"schemaVersion"`
	GeneratedAt     string           `json:"generatedAt"`
	InputURL        string           `json:"inputUrl"`
	FinalURL        *string          `json:"finalUrl,omitempty"`
	Reachable       bool             `json:"reachable"`
	OverallStatus   string           `json:"overallStatus"`
	HealthScore     int              `json:"healthScore"`
	Critical        []Finding        `json:"critical"`
	Warnings        []Finding        `json:"warnings"`
	Info            []Finding        `json:"info"`
	Checks          Checks           `json:"checks"`
	Recommendations []Recommendation `json:"recommendations"`
	Commands        []Command        `json:"commands"`
}

// Finding is a single observation about the target. Evidence is an untyped map
// because each check contributes a different, schema-documented payload; this
// is the one intentional use of map[string]interface{} in the codebase and is
// specified in docs/report-schema.md.
type Finding struct {
	Severity    string                 `json:"severity"`
	Layer       string                 `json:"layer"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Owner       string                 `json:"owner"`
}

// Recommendation is an actionable remediation step derived from findings.
type Recommendation struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	Priority    string `json:"priority"`
}

// Command is a shell command the reader can run to reproduce or verify a
// finding. Commands are constructed from validated host names only.
type Command struct {
	Title       string `json:"title"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// NewReport returns a report with all slices initialised so that JSON output
// contains empty arrays instead of null.
func NewReport(inputURL, generatedAt string) *Report {
	return &Report{
		SchemaVersion:   SchemaVersionValue,
		GeneratedAt:     generatedAt,
		InputURL:        inputURL,
		OverallStatus:   StatusError,
		Critical:        []Finding{},
		Warnings:        []Finding{},
		Info:            []Finding{},
		Recommendations: []Recommendation{},
		Commands:        []Command{},
		Checks:          NewChecks(),
	}
}

// SchemaVersionValue mirrors shared.SchemaVersion. It is duplicated here to
// keep the types package free of internal imports.
const SchemaVersionValue = "1.0.0"

// AddFinding files f into the bucket matching its severity.
func (r *Report) AddFinding(f Finding) {
	switch f.Severity {
	case SeverityCritical:
		r.Critical = append(r.Critical, f)
	case SeverityWarning:
		r.Warnings = append(r.Warnings, f)
	default:
		f.Severity = SeverityInfo
		r.Info = append(r.Info, f)
	}
}

// HasCritical reports whether the scan produced at least one critical finding.
func (r *Report) HasCritical() bool { return len(r.Critical) > 0 }

// HasWarnings reports whether the scan produced at least one warning.
func (r *Report) HasWarnings() bool { return len(r.Warnings) > 0 }
