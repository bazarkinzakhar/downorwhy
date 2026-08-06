package types

const (
	CheckStatusPass    = "pass"
	CheckStatusWarn    = "warn"
	CheckStatusFail    = "fail"
	CheckStatusSkipped = "skipped"
	CheckStatusError   = "error"
)

const (
	CheckDNS         = "dns"
	CheckTLS         = "tls"
	CheckHTTP        = "http"
	CheckRedirects   = "redirects"
	CheckHeaders     = "headers"
	CheckCDNCache    = "cdnCache"
	CheckPerformance = "performance"
	CheckSecurity    = "security"
	CheckIPv46       = "ipv46"
)

type CheckResult struct {
	Name       string                 `json:"name"`
	Status     string                 `json:"status"`
	DurationMS int64                  `json:"durationMs"`
	Summary    string                 `json:"summary"`
	Details    map[string]interface{} `json:"details"`
	Findings   []Finding              `json:"findings"`
	Error      string                 `json:"error,omitempty"`
}

type Checks struct {
	DNS         CheckResult `json:"dns"`
	TLS         CheckResult `json:"tls"`
	HTTP        CheckResult `json:"http"`
	Redirects   CheckResult `json:"redirects"`
	Headers     CheckResult `json:"headers"`
	CDNCache    CheckResult `json:"cdnCache"`
	Performance CheckResult `json:"performance"`
	Security    CheckResult `json:"security"`
	IPv46       CheckResult `json:"ipv46"`
}

func NewCheckResult(name string) CheckResult {
	return CheckResult{
		Name:     name,
		Status:   CheckStatusSkipped,
		Summary:  "check has not run",
		Details:  map[string]interface{}{},
		Findings: []Finding{},
	}
}

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
		IPv46:       NewCheckResult(CheckIPv46),
	}
}

func (c Checks) All() []CheckResult {
	return []CheckResult{
		c.DNS, c.TLS, c.HTTP, c.Redirects,
		c.Headers, c.CDNCache, c.Performance, c.Security, c.IPv46,
	}
}

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

func (r *CheckResult) Set(key string, value interface{}) {
	if r.Details == nil {
		r.Details = map[string]interface{}{}
	}
	r.Details[key] = value
}
