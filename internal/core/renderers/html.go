package renderers

import (
	_ "embed"
	"html/template"
	"io"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// htmlTemplate is a minimal, self-contained HTML page for a DownOrWhy report.
// No JavaScript, no external resources, no cookies, no tracking.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DownOrWhy report for {{.InputURL}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:960px;margin:0 auto;padding:2rem;color:#1a1a1a;background:#fff;line-height:1.6}
h1{font-size:1.8rem;margin-bottom:.25rem}
h2{font-size:1.3rem;margin-top:2rem;border-bottom:1px solid #e0e0e0;padding-bottom:.25rem}
h3{font-size:1.05rem;margin:1rem 0 .25rem}
.meta{color:#666;font-size:.9rem}
.score{font-size:2rem;font-weight:700}
.score.healthy{color:#2e7d32}
.score.degraded{color:#e65100}
.score.down{color:#c62828}
.score.error{color:#6a1b9a}
.finding{padding:.75rem;margin:.5rem 0;border-radius:4px;border-left:4px solid}
.finding.critical{border-color:#c62828;background:#fff5f5}
.finding.warning{border-color:#e65100;background:#fff8f0}
.finding.info{border-color:#1565c0;background:#f5f8ff}
table{border-collapse:collapse;width:100%;margin:1rem 0}
td,th{border:1px solid #e0e0e0;padding:.5rem .75rem;text-align:left}
th{background:#f5f5f5;font-weight:600}
code{background:#f0f0f0;padding:.15em .4em;border-radius:3px;font-size:.9em}
pre{background:#f5f5f5;padding:1rem;border-radius:4px;overflow-x:auto}
</style>
</head>
<body>
<h1>DownOrWhy report</h1>
<p class="meta"><strong>URL:</strong> {{.InputURL}}</p>
{{if .FinalURL}}<p class="meta"><strong>Final URL:</strong> {{.FinalURL}}</p>{{end}}
<p class="meta"><strong>Generated:</strong> {{.GeneratedAt}}</p>
<p class="meta"><strong>Reachable:</strong> {{.Reachable}}</p>
<p><span class="score {{.OverallStatus}}">{{.HealthScore}}/100</span> — {{.OverallStatus}}</p>

{{if .Critical}}
<h2>Critical findings</h2>
{{range .Critical}}
<div class="finding critical">
<h3>{{.Title}}</h3>
<p>{{.Description}}</p>
<p class="meta">Layer: {{.Layer}} · Owner: {{.Owner}}</p>
</div>
{{end}}
{{end}}

{{if .Warnings}}
<h2>Warnings</h2>
{{range .Warnings}}
<div class="finding warning">
<h3>{{.Title}}</h3>
<p>{{.Description}}</p>
<p class="meta">Layer: {{.Layer}} · Owner: {{.Owner}}</p>
</div>
{{end}}
{{end}}

<h2>Check summary</h2>
<table>
<tr><th>Check</th><th>Status</th><th>Duration</th><th>Summary</th></tr>
{{range .Checks.All}}
<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.DurationMS}}ms</td><td>{{.Summary}}</td></tr>
{{end}}
</table>

{{if .Recommendations}}
<h2>Recommendations</h2>
{{range .Recommendations}}
<p><strong>[{{.Priority | upper}}]</strong> {{.Title}} — {{.Description}} <em>({{.Owner}})</em></p>
{{end}}
{{end}}

{{if .Commands}}
<h2>Verification commands</h2>
{{range .Commands}}
<h3>{{.Title}}</h3>
<pre>{{.Command}}</pre>
<p>{{.Description}}</p>
{{end}}
{{end}}
</body>
</html>`

var parsedHTMLTemplate = template.Must(
	template.New("report").Funcs(template.FuncMap{
		"upper": func(s string) string {
			return s // simplified; the template just displays priority as-is
		},
	}).Parse(htmlTemplate),
)

// HTML writes a self-contained HTML report to w.
func HTML(w io.Writer, report *types.Report) error {
	return parsedHTMLTemplate.Execute(w, report)
}
