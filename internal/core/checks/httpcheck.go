package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RunHTTP evaluates the HTTP-level observations gathered by network.Client.
// It does not make another request: all HTTP-dependent checks use the single
// bounded request performed by the scanner.
func RunHTTP(response *network.Response) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckHTTP)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusError
		result.Error = "no HTTP response was available"
		result.Summary = "HTTP request did not produce a response"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	result.Set("statusCode", response.StatusCode)
	result.Set("status", response.Status)
	result.Set("protocol", response.Proto)
	result.Set("contentType", response.Header.Get("Content-Type"))
	result.Set("contentEncoding", response.ContentEncoding)
	result.Set("compressed", response.Compressed)
	result.Set("contentLength", response.ContentLength)
	result.Set("receivedBodyBytes", len(response.Body))
	result.Set("bodyTruncated", response.BodyTruncated)

	if response.FinalURL != nil {
		result.Set("finalURL", response.FinalURL.String())
	}

	switch {
	case response.StatusCode >= 500:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerHTTP,
			Title:    fmt.Sprintf("Server returned HTTP %d", response.StatusCode),
			Description: "The server accepted the request but failed while processing it. " +
				"This is usually an application, upstream dependency, deployment, or hosting failure.",
			Evidence: map[string]interface{}{
				"statusCode": response.StatusCode,
				"status":     response.Status,
			},
			Owner: types.OwnerBackend,
		})
	case response.StatusCode >= 400:
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHTTP,
			Title:    fmt.Sprintf("Server returned HTTP %d", response.StatusCode),
			Description: "The server responded, but the requested URL was not served successfully. " +
				"Check application routing, access-control rules, authentication middleware, and " +
				"whether the scanned URL is the intended public endpoint.",
			Evidence: map[string]interface{}{
				"statusCode": response.StatusCode,
				"status":     response.Status,
			},
			Owner: types.OwnerBackend,
		})
	case response.StatusCode >= 300:
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerHTTP,
			Title:    fmt.Sprintf("Final response is HTTP %d", response.StatusCode),
			Description: "The final URL returned a redirect status instead of content. " +
				"Review redirect findings to determine whether this is expected.",
			Evidence: map[string]interface{}{
				"statusCode": response.StatusCode,
				"status":     response.Status,
			},
			Owner: types.OwnerDevOps,
		})
	}

	if response.BodyTruncated {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHTTP,
			Title:    "Response body exceeded the scan safety limit",
			Description: "DownOrWhy stopped reading the response after the configured body-size limit. " +
				"The response may be substantially larger than expected, and content-based checks " +
				"were performed only on the retained prefix.",
			Evidence: map[string]interface{}{
				"maxBodyBytes": len(response.Body),
			},
			Owner: types.OwnerBackend,
		})
	}

	if !response.Compressed && isCompressibleContentType(response.Header.Get("Content-Type")) {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerHTTP,
			Title:    "Response is not compressed",
			Description: "The response did not declare a content encoding. Compression is usually " +
				"beneficial for text-based content, although it is not useful for already compressed " +
				"formats such as images, video, archives, or most modern fonts.",
			Evidence: map[string]interface{}{
				"contentType": response.Header.Get("Content-Type"),
			},
			Owner: types.OwnerBackend,
		})
	}

	if response.Proto == "HTTP/1.1" {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerHTTP,
			Title:    "HTTP/2 was not negotiated",
			Description: "The request completed over HTTP/1.1. HTTP/2 can reduce connection overhead " +
				"for pages that load many resources, but HTTP/1.1 is still valid and this is not an outage.",
			Evidence: map[string]interface{}{
				"protocol": response.Proto,
			},
			Owner: types.OwnerDevOps,
		})
	}

	result.Summary = fmt.Sprintf(
		"received %s over %s in %dms",
		response.Status,
		response.Proto,
		response.Timings.TotalMS,
	)
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

// isCompressibleContentType reports whether compression would plausibly help.
// Images, video, archives and modern font formats are already compressed, so
// reporting them as uncompressed would be noise rather than a finding.
func isCompressibleContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "" {
		return false
	}

	switch {
	case strings.HasPrefix(mediaType, "text/"):
		return true
	case strings.HasPrefix(mediaType, "image/svg"):
		return true
	case strings.HasSuffix(mediaType, "+json"), strings.HasSuffix(mediaType, "+xml"):
		return true
	}

	switch mediaType {
	case "application/json", "application/xml", "application/javascript",
		"application/x-javascript", "application/ld+json", "application/wasm":
		return true
	}

	return false
}