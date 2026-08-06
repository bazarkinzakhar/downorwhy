package renderers

import (
	"fmt"
	"io"
	"strings"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Short writes a compact terminal report: one status line, one line per
// finding, a one-line checks summary, and verification commands.
func Short(w io.Writer, report *types.Report) error {
	p := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	icon := map[string]string{
		types.SeverityCritical: "❌",
		types.SeverityWarning:  "⚠️",
		types.SeverityInfo:     "ℹ️",
	}

	p("DownOrWhy %s — %s (%d/100)", report.InputURL, report.OverallStatus, report.HealthScore)

	for _, f := range report.Critical {
		p("  %s %s: %s [%s]", icon[f.Severity], f.Layer, f.Title, f.Owner)
	}
	for _, f := range report.Warnings {
		p("  %s %s: %s [%s]", icon[f.Severity], f.Layer, f.Title, f.Owner)
	}

	if len(report.Critical)+len(report.Warnings) == 0 {
		p("  ✅ No issues found")
	}

	p("")
	p("Checks: %s", checksOneLine(report))

	if len(report.Commands) > 0 {
		p("")
		for _, c := range report.Commands {
			p("  $ %s", c.Command)
		}
	}

	return nil
}

func checksOneLine(report *types.Report) string {
	parts := make([]string, 0, 9)
	for _, cr := range report.Checks.All() {
		symbol := "."
		switch cr.Status {
		case types.CheckStatusFail:
			symbol = "F"
		case types.CheckStatusWarn:
			symbol = "W"
		case types.CheckStatusPass:
			symbol = "P"
		case types.CheckStatusSkipped:
			symbol = "-"
		case types.CheckStatusError:
			symbol = "E"
		}
		parts = append(parts, cr.Name+":"+symbol)
	}
	return strings.Join(parts, " ")
}
