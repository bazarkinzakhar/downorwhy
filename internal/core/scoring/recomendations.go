package scoring

import (
	"fmt"
	"strings"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Generate produces recommendations and verification commands from findings.
func Generate(report *types.Report, host string) {
	seen := map[string]struct{}{}

	for _, f := range report.Critical {
		rec := findingToRecommendation(f, host)
		if _, ok := seen[rec.Title]; !ok {
			report.Recommendations = append(report.Recommendations, rec)
			seen[rec.Title] = struct{}{}
		}
		cmd := findingToCommand(f, host)
		if cmd != nil {
			report.Commands = append(report.Commands, *cmd)
		}
	}
	for _, f := range report.Warnings {
		rec := findingToRecommendation(f, host)
		if _, ok := seen[rec.Title]; !ok {
			report.Recommendations = append(report.Recommendations, rec)
			seen[rec.Title] = struct{}{}
		}
	}
}

func findingToRecommendation(f types.Finding, host string) types.Recommendation {
	return types.Recommendation{
		Title:       f.Title,
		Description: f.Description,
		Owner:       OwnerDisplay(f.Owner),
		Priority:    severityToPriority(f.Severity),
	}
}

func severityToPriority(s string) string {
	switch s {
	case types.SeverityCritical:
		return types.PriorityCritical
	case types.SeverityWarning:
		return types.PriorityHigh
	default:
		return types.PriorityMedium
	}
}

func findingToCommand(f types.Finding, host string) *types.Command {
	switch {
	case strings.Contains(f.Title, "does not resolve"):
		return &types.Command{
			Title:       "Check DNS resolution",
			Command:     fmt.Sprintf("dig +short %s A && dig +short %s AAAA", host, host),
			Description: "Verify that the domain resolves to at least one IP address.",
		}
	case strings.Contains(f.Title, "TLS certificate has expired"):
		return &types.Command{
			Title:       "Check certificate expiry",
			Command:     fmt.Sprintf("echo | openssl s_client -servername %s -connect %s:443 2>/dev/null | openssl x509 -noout -dates", host, host),
			Description: "Inspect the certificate's validity period.",
		}
	case strings.Contains(f.Title, "does not match the host name"):
		return &types.Command{
			Title:       "Check certificate SAN",
			Command:     fmt.Sprintf("echo | openssl s_client -servername %s -connect %s:443 2>/dev/null | openssl x509 -noout -ext subjectAltName", host, host),
			Description: "Verify that the certificate covers the expected host name.",
		}
	case strings.Contains(f.Title, "HSTS header is missing"):
		return &types.Command{
			Title:       "Check HSTS header",
			Command:     fmt.Sprintf("curl -sI https://%s | grep -i strict-transport-security", host),
			Description: "Verify that the Strict-Transport-Security header is present.",
		}
	}
	return nil
}
