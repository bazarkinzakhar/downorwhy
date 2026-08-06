package types_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/types"
	"github.com/stretchr/testify/require"
)

func TestNewReportSerialisesEmptyArrays(t *testing.T) {
	r := types.NewReport("https://example.com", "2026-01-01T00:00:00Z")
	raw, err := json.Marshal(r)
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for _, key := range []string{"critical", "warnings", "info", "recommendations", "commands"} {
		require.JSONEq(t, "[]", string(decoded[key]), "field %s", key)
	}
	_, hasFinal := decoded["finalUrl"]
	require.False(t, hasFinal, "finalUrl must be omitted when nil")
}

func TestReportAddFindingRouting(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		critical int
		warnings int
		info     int
	}{
		{"critical", types.SeverityCritical, 1, 0, 0},
		{"warning", types.SeverityWarning, 0, 1, 0},
		{"info", types.SeverityInfo, 0, 0, 1},
		{"unknown falls back to info", "bogus", 0, 0, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := types.NewReport("https://example.com", "2026-01-01T00:00:00Z")
			r.AddFinding(types.Finding{Severity: tc.severity, Layer: types.LayerHTTP, Title: "t"})
			require.Len(t, r.Critical, tc.critical)
			require.Len(t, r.Warnings, tc.warnings)
			require.Len(t, r.Info, tc.info)
		})
	}
}

func TestCheckResultStatusEscalation(t *testing.T) {
	res := types.NewCheckResult(types.CheckHTTP)
	require.Equal(t, types.CheckStatusSkipped, res.Status)

	res.AddFinding(types.Finding{Severity: types.SeverityWarning})
	require.Equal(t, types.CheckStatusWarn, res.Status)

	res.AddFinding(types.Finding{Severity: types.SeverityCritical})
	require.Equal(t, types.CheckStatusFail, res.Status)

	res.AddFinding(types.Finding{Severity: types.SeverityWarning})
	require.Equal(t, types.CheckStatusFail, res.Status, "fail must not be downgraded")
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*types.Config)
		ok     bool
	}{
		{"defaults", func(*types.Config) {}, true},
		{"timeout too small", func(c *types.Config) { c.Timeout = 10 * time.Millisecond }, false},
		{"timeout too large", func(c *types.Config) { c.Timeout = 5 * time.Minute }, false},
		{"redirects too many", func(c *types.Config) { c.MaxRedirects = 11 }, false},
		{"body too large", func(c *types.Config) { c.MaxBodyBytes = 64 << 20 }, false},
		{"bad format", func(c *types.Config) { c.Format = "pdf" }, false},
		{"bad fail-on", func(c *types.Config) { c.FailOn = "always" }, false},
		{"empty user agent", func(c *types.Config) { c.UserAgent = "" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := types.DefaultConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, types.ErrInvalidConfig)
		})
	}
}

func TestConfigShouldFail(t *testing.T) {
	crit := types.NewReport("https://example.com", "t")
	crit.AddFinding(types.Finding{Severity: types.SeverityCritical})
	warn := types.NewReport("https://example.com", "t")
	warn.AddFinding(types.Finding{Severity: types.SeverityWarning})
	clean := types.NewReport("https://example.com", "t")

	tests := []struct {
		failOn string
		report *types.Report
		want   bool
	}{
		{types.FailOnCritical, crit, true},
		{types.FailOnCritical, warn, false},
		{types.FailOnWarning, warn, true},
		{types.FailOnWarning, clean, false},
		{types.FailOnNever, crit, false},
	}
	for _, tc := range tests {
		cfg := types.DefaultConfig()
		cfg.FailOn = tc.failOn
		require.Equal(t, tc.want, cfg.ShouldFail(tc.report), "failOn=%s", tc.failOn)
	}
}

func TestScanErrorExitCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, types.ExitOK},
		{"unsafe target", types.NewScanError("security", "validate", types.ErrUnsafeTarget), types.ExitInvalidUse},
		{"invalid url", types.NewScanError("input", "parse", types.ErrInvalidURL), types.ExitInvalidUse},
		{"timeout", types.NewScanError("http", "get", types.ErrTimeout), types.ExitUnreachable},
		{"unreachable", types.NewScanError("dns", "resolve", types.ErrUnreachable), types.ExitUnreachable},
		{"internal", types.NewScanError("render", "html", types.ErrInternal), types.ExitInternal},
		{"unwrapped foreign error", errors.New("boom"), types.ExitInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, types.ExitCodeOf(tc.err))
		})
	}
}

func TestScanErrorUnwrap(t *testing.T) {
	err := types.NewScanError(types.LayerTLS, "handshake", types.ErrTimeout)
	require.ErrorIs(t, err, types.ErrTimeout)
	require.Equal(t, "tls/handshake: operation timed out", err.Error())
}
