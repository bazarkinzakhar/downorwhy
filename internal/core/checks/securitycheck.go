package checks

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RunSecurity evaluates security-relevant properties of the target response:
// server identity disclosure, mixed content references in HTML, directory
// listing indicators, and the resolved IP address posture against the SSRF
// deny list, all from the single already-collected response.
func RunSecurity(
	response *network.Response,
	policy dowurl.Policy,
) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckSecurity)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusSkipped
		result.Summary = "security checks were skipped because no HTTP response was available"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	headers := response.Header

	// ── Server identity disclosure ──────────────────────────────────────

	if server := strings.TrimSpace(headers.Get("Server")); server != "" {
		result.Set("server", server)
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerSecurity,
			Title:    "Server header discloses software and version",
			Description: "The Server response header reveals the web server software and version. " +
				"This helps attackers select targeted exploits. Suppress or generalise it " +
				"(for example, 'webserver' instead of 'Apache/2.4.59').",
			Evidence: map[string]interface{}{"server": server},
			Owner:    types.OwnerSecurity,
		})
	}

	if poweredBy := strings.TrimSpace(headers.Get("X-Powered-By")); poweredBy != "" {
		result.Set("xPoweredBy", poweredBy)
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerSecurity,
			Title:    "X-Powered-By header discloses application framework",
			Description: "The X-Powered-By header reveals which application framework or language " +
				"generated the response. Remove it in production to reduce the information available " +
				"to attackers fingerprinting the stack.",
			Evidence: map[string]interface{}{"xPoweredBy": poweredBy},
			Owner:    types.OwnerSecurity,
		})
	}

	if aspNet := strings.TrimSpace(headers.Get("X-AspNet-Version")); aspNet != "" {
		result.Set("xAspNetVersion", aspNet)
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerSecurity,
			Title:    "X-AspNet-Version header discloses runtime version",
			Description: "The X-AspNet-Version header reveals the .NET CLR version. Disable it " +
				"through web.config or applicationhost.config.",
			Evidence: map[string]interface{}{"xAspNetVersion": aspNet},
			Owner:    types.OwnerSecurity,
		})
	}

	// ── Mixed content ───────────────────────────────────────────────────

	if response.FinalURL != nil &&
		response.FinalURL.Scheme == "https" &&
		len(response.Body) > 0 &&
		isHTMLLikeContent(headers.Get("Content-Type")) {
		count := countMixedContentReferences(response.Body)
		result.Set("mixedContentReferences", count)

		if count > 0 {
			result.AddFinding(types.Finding{
				Severity: types.SeverityCritical,
				Layer:    types.LayerSecurity,
				Title:    "HTTPS page references HTTP resources (mixed content)",
				Description: fmt.Sprintf(
					"The HTTPS response body contains approximately %d reference(s) to HTTP "+
						"resources. Browsers will block active mixed content such as scripts and "+
						"stylesheets and will warn about passive mixed content such as images. "+
						"All sub-resources must be loaded over HTTPS.",
					count,
				),
				Evidence: map[string]interface{}{
					"estimatedHttpReferences": count,
				},
				Owner: types.OwnerFrontend,
			})
		}
	}

	// ── Directory listing ───────────────────────────────────────────────

	if len(response.Body) > 0 && looksLikeDirectoryListing(response.Body) {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerSecurity,
			Title:    "Directory listing may be enabled",
			Description: "The response contains patterns consistent with an auto-generated " +
				"directory listing page. Directory listings expose internal file structures and " +
				"may inadvertently leak configuration files, backups, or credentials. Disable " +
				"directory listing in the web server configuration.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerSecurity,
		})
	}

	// ── IP address posture ──────────────────────────────────────────────

	if response.RemoteAddr.IsValid() {
		reason := dowurl.ReasonFor(response.RemoteAddr)
		if reason == "" {
			result.Set("remoteAddr", response.RemoteAddr.String())
		}
		// When reason is non-empty the dialer should have already rejected
		// the connection unless AllowPrivateTargets is set. The finding,
		// if any, is produced by the URL/dial safety layer, not here.
	}

	result.Summary = "evaluated security posture of the HTTP response"
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

// ── helpers ────────────────────────────────────────────────────────────────

// isHTMLLikeContent reports whether contentType describes an HTML resource
// whose body should be scanned for mixed-content references.
func isHTMLLikeContent(contentType string) bool {
	media := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))

	return strings.HasPrefix(media, "text/html") || media == "application/xhtml+xml"
}

// countMixedContentReferences estimates the number of http:// scheme
// references in an HTML body. It scans for common attribute patterns without
// a full HTML parser. The count is an approximation; false positives from
// http:// appearing in visible text are possible but rare in practice.
func countMixedContentReferences(body []byte) int {
	lowerBody := bytes.ToLower(body)
	count := 0

	patterns := []string{
		`src="http://`,
		`href="http://`,
		`url("http://`,
		`url('http://`,
		`url(http://`,
	}

	for _, pattern := range patterns {
		count += bytes.Count(lowerBody, []byte(pattern))
	}

	return count
}

// looksLikeDirectoryListing checks for HTML title and heading patterns that
// strongly indicate an auto-generated directory listing page.
func looksLikeDirectoryListing(body []byte) bool {
	if len(body) < 64 {
		return false
	}

	window := body[:min(len(body), 4096)]
	lowerWindow := bytes.ToLower(window)

	indicators := [][]byte{
		[]byte("<title>index of "),
		[]byte("<h1>index of "),
		[]byte("<title>directory listing for"),
		[]byte(">index of /"),
		[]byte("<a href=\"/\">parent directory</a>"),
	}

	for _, indicator := range indicators {
		if bytes.Contains(lowerWindow, indicator) {
			return true
		}
	}

	return false
}
