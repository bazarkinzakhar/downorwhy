package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/downorwhy/downorwhy/internal/core/checks"
	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/scoring"
	"github.com/downorwhy/downorwhy/internal/core/types"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
)

// Scan runs the complete pipeline against rawURL and returns a finished
// report. The report is populated even when the target is unreachable, so
// callers always have diagnostic information. Scan returns a non-nil error
// only when the input is invalid or the target is blocked by the SSRF policy.
func Scan(ctx context.Context, rawURL string, cfg types.Config, logger zerolog.Logger) (*types.Report, error) {
	report := types.NewReport(rawURL, time.Now().UTC().Format(time.RFC3339))

	target, err := dowurl.Normalize(rawURL)
	if err != nil {
		report.OverallStatus = types.StatusError
		report.AddFinding(types.Finding{
			Severity:    types.SeverityCritical,
			Layer:       types.LayerHTTP,
			Title:       "Invalid URL",
			Description: fmt.Sprintf("The provided URL could not be parsed: %s", err),
			Owner:       types.OwnerUser,
		})
		return report, err
	}

	policy := dowurl.DefaultPolicy()
	if cfg.AllowPrivateTargets {
		policy = dowurl.Policy{AllowPrivate: true}
	}
	if err := policy.CheckTarget(target); err != nil {
		report.OverallStatus = types.StatusError
		report.AddFinding(types.Finding{
			Severity:    types.SeverityCritical,
			Layer:       types.LayerSecurity,
			Title:       "Unsafe target rejected",
			Description: fmt.Sprintf("DownOrWhy refused to scan this target: %s", err),
			Owner:       types.OwnerUser,
		})
		return report, err
	}

	logger.Info().Str("url", target.String()).Msg("scan starting")

	dnsClient := network.NewDNSClient(cfg.Timeout)
	dnsResult := dnsClient.Resolve(ctx, target.Host)
	report.Checks.DNS = checks.RunDNS(ctx, target.Host, dnsClient)

	if target.IsHTTPS() {
		safeDialer := network.NewSafeDialer(policy, nil, cfg.Timeout)
		tlsClient := network.NewTLSClient(network.TLSClientOptions{
			Dialer:  safeDialer,
			Timeout: cfg.Timeout,
		})
		report.Checks.TLS = checks.RunTLS(ctx, target.Host, target.HostPort(), tlsClient)
	} else {
		report.Checks.TLS = types.NewCheckResult(types.CheckTLS)
		report.Checks.TLS.Status = types.CheckStatusSkipped
		report.Checks.TLS.Summary = "TLS check skipped for plaintext HTTP target"
	}

	httpClient := network.NewClient(network.ClientOptions{
		Config:   cfg,
		Policy:   policy,
	})
	response, _ := httpClient.Fetch(ctx, target)

	report.Reachable = response != nil
	if response != nil && response.FinalURL != nil {
		u := dowurl.Display(response.FinalURL, cfg.Redact)
		report.FinalURL = &u
	} else {
		u := dowurl.Display(target.URL, cfg.Redact)
		report.FinalURL = &u
	}

	report.Checks.HTTP = checks.RunHTTP(response)
	report.Checks.Redirects = checks.RunRedirects(target, response, policy)
	report.Checks.Headers = checks.RunHeaders(response)
	report.Checks.CDNCache = checks.RunCDNCache(response)
	report.Checks.Performance = checks.RunPerformance(response)
	report.Checks.Security = checks.RunSecurity(response, policy)
	report.Checks.IPv46 = checks.RunIPv46(dnsResult, response)

	for _, cr := range report.Checks.All() {
		for _, f := range cr.Findings {
			report.AddFinding(f)
		}
	}

	report.HealthScore, report.OverallStatus = scoring.Score(report.Checks, report.Reachable)
	scoring.Generate(report, target.Host)

	logger.Info().
		Int("score", report.HealthScore).
		Str("status", report.OverallStatus).
		Int("critical", len(report.Critical)).
		Int("warnings", len(report.Warnings)).
		Msg("scan complete")

	return report, nil
}
