package types

// Check status values.
const (
	CheckStatusPass    = "pass"
	CheckStatusWarn    = "warn"
	CheckStatusFail    = "fail"
	CheckStatusSkipped = "skipped"
	CheckStatusError   = "error"
)

// Check identifiers, used as map keys, CLI filters and documentation anchors.
const (
	CheckDNS         = "dns"
	CheckTLS         = "tls"
	CheckHTTP        = "http"
	CheckRedirects   = "redirects"
	CheckHeaders     = "headers"
	CheckCDNCache    = "cdnCache"
	CheckPerformance = "performance"
	CheckSecurity    = "security"
)

// CheckResult is the output of a single check package. Details carries the
// check-specific payload documented in docs/report-schema.md.
type CheckResult struct {
	Name       string                 `json:"name"`
	Status     string                 `json:"status"`
	DurationMS int64                  `json:"durationMs"`
	Summary    string                 `json:"summary"`
	Details    map[string]interface{} `json:"details"`
	Findings   []Finding              `json:"findings"`
	Error      string                 `json:"error,omitempty"`
}

// Checks aggregates every check result of a scan.
type Checks struct {
	DNS         CheckResult `json:"dns"`
	TLS         CheckResult `json:"tls"`
	HTTP        CheckResult `json:"http"`
	Redirects   CheckResult `json:"redirects"`
	Headers     CheckResult `json:"headers"`
	CDNCache    CheckResult `json:"cdnCache"`
	Performance CheckResult `json:"performance"`
	Security    CheckResult `json:"security"`
}

// NewCheckResult returns a skipped result for the named check with
// initialised containers.
func NewCheckResult(name string) CheckResult {
	return CheckResult{
		Name:     name,
		Status:   CheckStatusSkipped,
		Summary:  "check has not run",
		Details:  map[string]interface{}{},
		Findings: []Finding{},
	}
}

// NewChecks returns a Checks value where every check is marked as skipped.
func NewChecks() Checks {
	return Checks{
		DNS:         NewCheckResult(CheckDNS),
		TLS:         NewCheckResult(CheckTLS),
		HTTP:        NewCheckResult(CheckHTTP),
		Redirects:   NewCheckResult(CheckRedirects),
		Headers:     NewCheckResult(CheckHeaders),
		CDNCache:    NewCheckResult(CheckCDNCache),
		Performance: NewCheckResult(CheckPerformance),
		Security:    NewCheckResult(CheckSecurity),
	}
}

// All returns the checks in report order. The slice is a copy; mutating it
// does not affect the receiver.
func (c Checks) All() []CheckResult {
	return []CheckResult{
		c.DNS, c.TLS, c.HTTP, c.Redirects,
		c.Headers, c.CDNCache, c.Performance, c.Security,
	}
}

// AddFinding appends f to the result and raises its status if needed.
func (r *CheckResult) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case SeverityCritical:
		r.Status = CheckStatusFail
	case SeverityWarning:
		if r.Status != CheckStatusFail {
			r.Status = CheckStatusWarn
		}
	}
}

// Set records a detail value for the check.
func (r *CheckResult) Set(key string, value interface{}) {
	if r.Details == nil {
		r.Details = map[string]interface{}{}
	}
	r.Details[key] = value
}
