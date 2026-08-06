package renderers

import (
	"fmt"
	"io"
	"strings"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Markdown writes a human-readable Markdown report to w.
func Markdown(w io.Writer, report *types.Report) error {
	p := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	p("# DownOrWhy report")
	p("")
	p("**URL:** %s", report.InputURL)
	if report.FinalURL != nil && *report.FinalURL != report.InputURL {
		p("**Final URL:** %s", *report.FinalURL)
	}
	p("**Generated:** %s", report.GeneratedAt)
	p("**Reachable:** %v", report.Reachable)
	p("**Status:** %s", report.OverallStatus)
	p("**Health score:** %d/100", report.HealthScore)
	p("")

	if len(report.Critical) > 0 {
		p("## Critical findings")
		p("")
		for _, f := range report.Critical {
			p("### %s", f.Title)
			p("")
			p("%s", f.Description)
			p("")
			p("- **Layer:** %s", f.Layer)
			p("- **Owner:** %s", f.Owner)
			p("")
		}
	}

	if len(report.Warnings) > 0 {
		p("## Warnings")
		p("")
		for _, f := range report.Warnings {
			p("### %s", f.Title)
			p("")
			p("%s", f.Description)
			p("")
			p("- **Layer:** %s", f.Layer)
			p("- **Owner:** %s", f.Owner)
			p("")
		}
	}

	if len(report.Info) > 0 && (len(report.Critical)+len(report.Warnings) == 0) {
		p("## Info")
		p("")
		for _, f := range report.Info {
			p("- **%s** — %s", f.Title, f.Description)
		}
		p("")
	}

	p("## Check summary")
	p("")
	p("| Check | Status | Duration | Summary |")
	p("| ----- | ------ | -------- | ------- |")
	for _, cr := range report.Checks.All() {
		p("| %s | %s | %dms | %s |", cr.Name, statusIcon(cr.Status), cr.DurationMS, cr.Summary)
	}
	p("")

	if len(report.Recommendations) > 0 {
		p("## Recommendations")
		p("")
		for _, r := range report.Recommendations {
			p("- **[%s]** %s — %s (%s)", strings.ToUpper(r.Priority), r.Title, r.Description, r.Owner)
		}
		p("")
	}

	if len(report.Commands) > 0 {
		p("## Verification commands")
		p("")
		for _, c := range report.Commands {
			p("### %s", c.Title)
			p("")
			p("```")
			p("%s", c.Command)
			p("```")
			p("")
			p("%s", c.Description)
			p("")
		}
	}

	return nil
}

func statusIcon(status string) string {
	switch status {
	case types.CheckStatusPass:
		return "✅ pass"
	case types.CheckStatusWarn:
		return "⚠️ warn"
	case types.CheckStatusFail:
		return "❌ fail"
	case types.CheckStatusSkipped:
		return "⏭️ skipped"
	case types.CheckStatusError:
		return "🔥 error"
	default:
		return status
	}
}
