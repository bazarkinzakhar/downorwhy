package renderers

import (
	"fmt"
	"io"
	"strings"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Text writes a plain-text report suitable for a terminal to w.
func Text(w io.Writer, report *types.Report) error {
	p := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	p("DownOrWhy report")
	p(strings.Repeat("=", 60))
	p("URL:         %s", report.InputURL)
	if report.FinalURL != nil && *report.FinalURL != report.InputURL {
		p("Final URL:   %s", *report.FinalURL)
	}
	p("Generated:   %s", report.GeneratedAt)
	p("Reachable:   %v", report.Reachable)
	p("Status:      %s", report.OverallStatus)
	p("Score:       %d/100", report.HealthScore)
	p("")

	if len(report.Critical) > 0 {
		p("CRITICAL")
		p(strings.Repeat("-", 60))
		for _, f := range report.Critical {
			p("  %s [%s]", f.Title, f.Owner)
			p("  %s", wordWrap(f.Description, 56))
			p("")
		}
	}

	if len(report.Warnings) > 0 {
		p("WARNINGS")
		p(strings.Repeat("-", 60))
		for _, f := range report.Warnings {
			p("  %s [%s]", f.Title, f.Owner)
			p("  %s", wordWrap(f.Description, 56))
			p("")
		}
	}

	p("CHECKS")
	p(strings.Repeat("-", 60))
	for _, cr := range report.Checks.All() {
		p("  %-12s %s  %dms  %s", cr.Name+":", statusIcon(cr.Status), cr.DurationMS, cr.Summary)
	}
	p("")

	if len(report.Commands) > 0 {
		p("VERIFICATION COMMANDS")
		p(strings.Repeat("-", 60))
		for _, c := range report.Commands {
			p("  $ %s", c.Command)
			p("  %s", c.Description)
			p("")
		}
	}

	return nil
}

func wordWrap(s string, width int) string {
	if len(s) <= width {
		return s
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	line := ""
	for _, w := range words {
		if len(line)+len(w)+1 > width && line != "" {
			lines = append(lines, line)
			line = w
		} else if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n    ")
}
