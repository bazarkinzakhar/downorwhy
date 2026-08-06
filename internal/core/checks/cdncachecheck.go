package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RunCDNCache evaluates CDN and HTTP cache headers from the single response
// collected during scanning. It never makes additional requests.
func RunCDNCache(response *network.Response) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckCDNCache)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusSkipped
		result.Summary = "CDN and cache headers were not checked because no HTTP response was available"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	headers := response.Header

	cacheControl := strings.TrimSpace(headers.Get("Cache-Control"))
	age := strings.TrimSpace(headers.Get("Age"))
	etag := strings.TrimSpace(headers.Get("ETag"))
	lastModified := strings.TrimSpace(headers.Get("Last-Modified"))
	vary := strings.TrimSpace(headers.Get("Vary"))
	xCache := strings.TrimSpace(headers.Get("X-Cache"))
	cfCacheStatus := strings.TrimSpace(headers.Get("CF-Cache-Status"))

	result.Set("cacheControl", cacheControl)
	result.Set("ageHeader", age)
	result.Set("hasETag", etag != "")
	result.Set("hasLastModified", lastModified != "")
	result.Set("vary", vary)
	result.Set("xCache", xCache)
	result.Set("cfCacheStatus", cfCacheStatus)

	// CDN detection and status evaluation.
	cdnDetected := false

	if cfCacheStatus != "" {
		cdnDetected = true
		result.Set("cdn", "Cloudflare")
		statusLower := strings.ToLower(cfCacheStatus)

		switch {
		case statusLower == "hit":
			// Healthy: resource served from CDN edge.
		case statusLower == "miss":
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerCDN,
				Title:    "Cloudflare cache miss",
				Description: "Cloudflare did not have this resource in cache. The request was forwarded " +
					"to the origin server. Repeated misses for the same resource increase origin load.",
				Evidence: map[string]interface{}{"cfCacheStatus": cfCacheStatus},
				Owner:    types.OwnerDevOps,
			})
		case statusLower == "bypass":
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerCDN,
				Title:    "Cloudflare cache bypassed",
				Description: "Cloudflare was configured to bypass the cache for this request. Check " +
					"page rules, worker routes, and cache configuration in the Cloudflare dashboard.",
				Evidence: map[string]interface{}{"cfCacheStatus": cfCacheStatus},
				Owner:    types.OwnerDevOps,
			})
		case statusLower == "expired":
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerCDN,
				Title:    "Cloudflare cached resource expired",
				Description: "The cached copy at Cloudflare has expired and the request was forwarded " +
					"to the origin. Consider increasing the cache TTL if this content changes infrequently.",
				Evidence: map[string]interface{}{"cfCacheStatus": cfCacheStatus},
				Owner:    types.OwnerDevOps,
			})
		case statusLower == "dynamic":
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerCDN,
				Title:    "Cloudflare marked resource as dynamic",
				Description: "Cloudflare treated this resource as dynamic and did not cache it. This " +
					"is expected for authenticated, personalised, or real-time content. Verify that " +
					"static assets are not incorrectly classified as dynamic.",
				Evidence: map[string]interface{}{"cfCacheStatus": cfCacheStatus},
				Owner:    types.OwnerBackend,
			})
		default:
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerCDN,
				Title:    fmt.Sprintf("Cloudflare returned unexpected cache status: %s", cfCacheStatus),
				Description: "Cloudflare returned a cache status value that DownOrWhy does not " +
					"recognise. Review the raw CF-Cache-Status header.",
				Evidence: map[string]interface{}{"cfCacheStatus": cfCacheStatus},
				Owner:    types.OwnerDevOps,
			})
		}
	}

	if xCache != "" && cfCacheStatus == "" {
		cdnDetected = true
		result.Set("cdn", "generic")
		xCacheLower := strings.ToLower(xCache)

		if strings.Contains(xCacheLower, "hit") {
			// Healthy.
		} else if strings.Contains(xCacheLower, "miss") {
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerCDN,
				Title:    "CDN cache miss (X-Cache)",
				Description: "The CDN reported a cache miss for this resource. The request was served " +
					"from the origin server rather than the edge.",
				Evidence: map[string]interface{}{"xCache": xCache},
				Owner:    types.OwnerDevOps,
			})
		}
	}

	result.Set("cdnDetected", cdnDetected)

	// Cache-Control analysis.
	ccLower := strings.ToLower(cacheControl)

	if cacheControl == "" && !cdnDetected {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerCache,
			Title:    "No Cache-Control header",
			Description: "The response does not define a Cache-Control header. Browsers and " +
				"intermediate caches will apply heuristic caching, which may not match the " +
				"intended behaviour and makes cache behaviour unpredictable.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerBackend,
		})
	}

	switch {
	case strings.Contains(ccLower, "no-store"):
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerCache,
			Title:    "Cache-Control prohibits all caching (no-store)",
			Description: "The response is marked no-store. Neither browsers nor CDNs will retain a " +
				"copy. This is appropriate for sensitive data but means every request reaches the origin.",
			Evidence: map[string]interface{}{"cacheControl": cacheControl},
			Owner:    types.OwnerBackend,
		})
	case strings.Contains(ccLower, "private"):
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerCache,
			Title:    "Cache-Control set to private",
			Description: "The response may be cached by browsers but not by shared caches or CDNs. " +
				"Origin load does not benefit from CDN-level caching for this resource.",
			Evidence: map[string]interface{}{"cacheControl": cacheControl},
			Owner:    types.OwnerBackend,
		})
	}

	// Set-Cookie / cache interaction: a response with both Set-Cookie and
	// a cacheable directive is a configuration smell because CDNs typically
	// strip cached copies when cookies are present.
	if len(headers.Values("Set-Cookie")) > 0 &&
		cacheControl != "" &&
		!strings.Contains(ccLower, "no-store") &&
		!strings.Contains(ccLower, "no-cache") &&
		!strings.Contains(ccLower, "private") {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerCache,
			Title:    "Response sets cookies with a cacheable Cache-Control directive",
			Description: "The response includes Set-Cookie headers alongside a Cache-Control value " +
				"that does not prohibit shared caching. CDNs and shared caches will typically strip " +
				"Set-Cookie from stored responses or bypass the cache entirely, making the " +
				"cacheable directive ineffective.",
			Evidence: map[string]interface{}{
				"cacheControl": cacheControl,
				"cookieCount":  len(headers.Values("Set-Cookie")),
			},
			Owner: types.OwnerBackend,
		})
	}

	result.Summary = formatCDNCacheSummary(cdnDetected, cacheControl, effectiveCDNStatus(cfCacheStatus, xCache))
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

func effectiveCDNStatus(cf, xc string) string {
	if cf != "" {
		return cf
	}
	if xc != "" {
		return xc
	}
	return ""
}

func formatCDNCacheSummary(cdnDetected bool, cacheControl, cdnStatus string) string {
	if cdnDetected && cdnStatus != "" {
		return fmt.Sprintf("CDN cache status: %s", cdnStatus)
	}
	if cacheControl != "" {
		return fmt.Sprintf("Cache-Control: %s", cacheControl)
	}
	return "no cache directives and no CDN detected"
}
