package checks

import (
	"fmt"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Performance thresholds, in milliseconds.
const (
	ttfbWarningMS  = 1500
	ttfbCriticalMS = 3000

	totalWarningMS  = 10000
	totalCriticalMS = 20000
)

// Response size thresholds, in bytes.
const (
	sizeWarningBytes  = 5 * 1024 * 1024
	sizeCriticalBytes = 15 * 1024 * 1024
)

// DNS and TLS latency thresholds, in milliseconds.
const (
	dnsSlowMS = 500
	tlsSlowMS = 1000
)

// Min throughput before a warning is raised, in KB/s.
const minThroughputKBs = 100

// RunPerformance evaluates the timing and size metrics captured during the
// HTTP transaction. It never makes additional requests.
func RunPerformance(response *network.Response) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckPerformance)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusSkipped
		result.Summary = "performance was not checked because no HTTP response was available"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	timings := response.Timings

	result.Set("dnsMs", timings.DNSMS)
	result.Set("connectMs", timings.ConnectMS)
	result.Set("tlsMs", timings.TLSMS)
	result.Set("ttfbMs", timings.TTFBMS)
	result.Set("downloadMs", timings.DownloadMS)
	result.Set("totalMs", timings.TotalMS)
	result.Set("responseBodyBytes", len(response.Body))
	result.Set("contentLengthDeclared", response.ContentLength)

	// ── TTFB ────────────────────────────────────────────────────────────

	switch {
	case timings.TTFBMS > ttfbCriticalMS:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("Time to first byte is critically slow: %d ms", timings.TTFBMS),
			Description: fmt.Sprintf(
				"The server took %d ms to send the first byte. TTFB above %d ms indicates a "+
					"severely overloaded or distant origin, a slow application, or a blocking upstream "+
					"dependency. Users will experience a noticeable white screen before the page begins "+
					"to load.",
				timings.TTFBMS, ttfbCriticalMS,
			),
			Evidence: map[string]interface{}{
				"ttfbMs":            timings.TTFBMS,
				"thresholdCritical": ttfbCriticalMS,
			},
			Owner: types.OwnerBackend,
		})
	case timings.TTFBMS > ttfbWarningMS:
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("Time to first byte is slow: %d ms", timings.TTFBMS),
			Description: fmt.Sprintf(
				"The server took %d ms to send the first byte. TTFB above %d ms may be "+
					"noticeable and indicates server-side processing delays that should be investigated.",
				timings.TTFBMS, ttfbWarningMS,
			),
			Evidence: map[string]interface{}{
				"ttfbMs":           timings.TTFBMS,
				"thresholdWarning": ttfbWarningMS,
			},
			Owner: types.OwnerBackend,
		})
	}

	// ── Total time ──────────────────────────────────────────────────────

	switch {
	case timings.TotalMS > totalCriticalMS:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("Total response time is critically slow: %d ms", timings.TotalMS),
			Description: fmt.Sprintf(
				"The complete request and response took %d ms. Total time above %d ms means "+
					"the page is effectively unusable for users on typical connections. This is a "+
					"service-level emergency.",
				timings.TotalMS, totalCriticalMS,
			),
			Evidence: map[string]interface{}{
				"totalMs":           timings.TotalMS,
				"thresholdCritical": totalCriticalMS,
			},
			Owner: types.OwnerBackend,
		})
	case timings.TotalMS > totalWarningMS:
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("Total response time is slow: %d ms", timings.TotalMS),
			Description: fmt.Sprintf(
				"The complete request and response took %d ms. Total time above %d ms is "+
					"noticeable and should be investigated. Break down the timings below to identify "+
					"which phase dominates.",
				timings.TotalMS, totalWarningMS,
			),
			Evidence: map[string]interface{}{
				"totalMs":          timings.TotalMS,
				"thresholdWarning": totalWarningMS,
			},
			Owner: types.OwnerBackend,
		})
	}

	// ── Response body size ──────────────────────────────────────────────

	bodySizeBytes := len(response.Body)

	switch {
	case bodySizeBytes > sizeCriticalBytes:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerPerformance,
			Title: fmt.Sprintf("Response body is critically large: %.1f MB",
				float64(bodySizeBytes)/(1024*1024)),
			Description: fmt.Sprintf(
				"The response body is %.1f MB. Responses above %.0f MB cause high data transfer "+
					"costs and unacceptably slow page loads on mobile and metered connections.",
				float64(bodySizeBytes)/(1024*1024), float64(sizeCriticalBytes)/(1024*1024),
			),
			Evidence: map[string]interface{}{
				"bodySizeBytes":     bodySizeBytes,
				"thresholdCritical": sizeCriticalBytes,
			},
			Owner: types.OwnerBackend,
		})
	case bodySizeBytes > sizeWarningBytes:
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("Response body is large: %.1f MB", float64(bodySizeBytes)/(1024*1024)),
			Description: fmt.Sprintf(
				"The response body is %.1f MB. Consider compression, pagination, "+
					"incremental loading, or content delivery optimisation to reduce the initial payload.",
				float64(bodySizeBytes)/(1024*1024),
			),
			Evidence: map[string]interface{}{
				"bodySizeBytes":     bodySizeBytes,
				"thresholdWarning": sizeWarningBytes,
			},
			Owner: types.OwnerBackend,
		})
	}

	// ── DNS timing ──────────────────────────────────────────────────────
	// DNSMS is -1 when the host was an IP literal and no DNS query occurred.

	if timings.DNSMS > dnsSlowMS {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("DNS lookup took %d ms", timings.DNSMS),
			Description: "The DNS lookup was noticeably slow. Consider a DNS provider with lower " +
				"latency or a CDN that serves DNS from edge locations close to your users.",
			Evidence: map[string]interface{}{"dnsMs": timings.DNSMS},
			Owner:    types.OwnerDNSProvider,
		})
	}

	// ── TLS timing ──────────────────────────────────────────────────────
	// TLSMS is -1 for plaintext HTTP connections.

	if timings.TLSMS > tlsSlowMS {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerPerformance,
			Title:    fmt.Sprintf("TLS handshake took %d ms", timings.TLSMS),
			Description: "The TLS handshake was slow. Possible causes include OCSP stapling " +
				"delays, a large server certificate chain, or server-side TLS processing overhead. " +
				"Verify that the server presents a complete chain, including intermediates.",
			Evidence: map[string]interface{}{"tlsMs": timings.TLSMS},
			Owner:    types.OwnerDevOps,
		})
	}

	// ── Approximate throughput ──────────────────────────────────────────

	if timings.DownloadMS > 0 && bodySizeBytes > 1024 {
		throughputKBs := float64(bodySizeBytes) / 1024.0 / (float64(timings.DownloadMS) / 1000.0)
		result.Set("approximateThroughputKBs", int(throughputKBs))

		if throughputKBs < minThroughputKBs {
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerPerformance,
				Title:    fmt.Sprintf("Download throughput is low: %.0f KB/s", throughputKBs),
				Description: "The effective download throughput is below 100 KB/s. This may be " +
					"caused by server rate-limiting, network congestion, a small TCP window, or " +
					"packet loss. Compare with throughput from a different network to isolate the cause.",
				Evidence: map[string]interface{}{
					"throughputKBs":        int(throughputKBs),
					"downloadDurationMs":   timings.DownloadMS,
					"transferredBodyBytes": bodySizeBytes,
				},
				Owner: types.OwnerHostingProvider,
			})
		}
	}

	result.Summary = fmt.Sprintf(
		"TTFB %d ms, total %d ms, %d response bytes",
		timings.TTFBMS,
		timings.TotalMS,
		bodySizeBytes,
	)
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}
