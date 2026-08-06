package checks_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/checks"
	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func cdnResponse(headers http.Header) *network.Response {
	finalURL, err := url.Parse("https://example.com/")
	if err != nil {
		panic(err)
	}

	normalized := make(http.Header)
	for k, v := range headers {
		for _, value := range v {
			normalized.Add(k, value)
		}
	}

	return &network.Response{
		FinalURL:   finalURL,
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/2.0",
		Header:     normalized,
	}
}

func TestRunCDNCacheNilResponseIsSkipped(t *testing.T) {
	result := checks.RunCDNCache(nil)

	require.Equal(t, types.CheckStatusSkipped, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunCDNCacheNoHeadersIsInformational(t *testing.T) {
	response := cdnResponse(http.Header{})

	result := checks.RunCDNCache(response)

	require.Equal(t, types.CheckStatusPass, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "No Cache-Control header" {
			found = true
			require.Equal(t, types.SeverityInfo, finding.Severity)
		}
	}
	require.True(t, found)
}

func TestRunCDNCacheCloudflareHit(t *testing.T) {
	response := cdnResponse(http.Header{
		"CF-Cache-Status": []string{"HIT"},
		"Cache-Control":   []string{"public, max-age=3600"},
	})

	result := checks.RunCDNCache(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunCDNCacheCloudflareBypassIsWarning(t *testing.T) {
	response := cdnResponse(http.Header{
		"CF-Cache-Status": []string{"BYPASS"},
	})

	result := checks.RunCDNCache(response)

	finding, found := findingWithTitle(result.Findings, "Cloudflare cache bypassed")
	require.True(t, found)
	require.Equal(t, types.SeverityWarning, finding.Severity)
	require.Equal(t, types.OwnerDevOps, finding.Owner)
}

func TestRunCDNCacheNoStore(t *testing.T) {
	response := cdnResponse(http.Header{
		"Cache-Control": []string{"no-store"},
	})

	result := checks.RunCDNCache(response)

	finding, found := findingWithTitle(result.Findings, "Cache-Control prohibits all caching (no-store)")
	require.True(t, found)
	require.Equal(t, types.SeverityInfo, finding.Severity)
}

func TestRunCDNCachePrivate(t *testing.T) {
	response := cdnResponse(http.Header{
		"Cache-Control": []string{"private, max-age=60"},
	})

	result := checks.RunCDNCache(response)

	_, found := findingWithTitle(result.Findings, "Cache-Control set to private")
	require.True(t, found)
}

func TestRunCDNCacheCookieWithCacheableDirectiveIsWarning(t *testing.T) {
	response := cdnResponse(http.Header{
		"Cache-Control": []string{"public, max-age=3600"},
		"Set-Cookie":    []string{"session=abc123; Path=/"},
	})

	result := checks.RunCDNCache(response)

	finding, found := findingWithTitle(result.Findings,
		"Response sets cookies with a cacheable Cache-Control directive")
	require.True(t, found)
	require.Equal(t, types.SeverityWarning, finding.Severity)
	require.Equal(t, types.OwnerBackend, finding.Owner)
}

func TestRunCDNCacheGenericXCacheMiss(t *testing.T) {
	response := cdnResponse(http.Header{
		"X-Cache": []string{"Miss from cloudfront"},
	})

	result := checks.RunCDNCache(response)

	finding, found := findingWithTitle(result.Findings, "CDN cache miss (X-Cache)")
	require.True(t, found)
	require.Equal(t, types.SeverityInfo, finding.Severity)
}
