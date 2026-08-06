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

func performanceResponse(timings network.Timings, bodySize int) *network.Response {
	finalURL, err := url.Parse("https://example.com/")
	if err != nil {
		panic(err)
	}

	return &network.Response{
		FinalURL:   finalURL,
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/2.0",
		Timings:    timings,
		Body:       make([]byte, bodySize),
	}
}

func TestRunPerformanceNilResponseIsSkipped(t *testing.T) {
	result := checks.RunPerformance(nil)

	require.Equal(t, types.CheckStatusSkipped, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunPerformanceHealthyResponsePasses(t *testing.T) {
	response := performanceResponse(network.Timings{
		DNSMS:      20,
		ConnectMS:  15,
		TLSMS:      45,
		TTFBMS:     200,
		DownloadMS: 50,
		TotalMS:    350,
	}, 50*1024)

	result := checks.RunPerformance(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunPerformanceSlowTTFBIsWarning(t *testing.T) {
	response := performanceResponse(network.Timings{
		TTFBMS:  2000,
		TotalMS: 2500,
	}, 1024)

	result := checks.RunPerformance(response)

	finding, found := findingWithTitle(result.Findings,
		"Time to first byte is slow: 2000 ms")
	require.True(t, found)
	require.Equal(t, types.SeverityWarning, finding.Severity)
}

func TestRunPerformanceCriticallySlowTTFBIsCritical(t *testing.T) {
	response := performanceResponse(network.Timings{
		TTFBMS:  4000,
		TotalMS: 5000,
	}, 1024)

	result := checks.RunPerformance(response)

	finding, found := findingWithTitle(result.Findings,
		"Time to first byte is critically slow: 4000 ms")
	require.True(t, found)
	require.Equal(t, types.SeverityCritical, finding.Severity)
}

func TestRunPerformanceCriticallySlowTotalIsCritical(t *testing.T) {
	response := performanceResponse(network.Timings{
		TTFBMS:  500,
		TotalMS: 25000,
	}, 1024)

	result := checks.RunPerformance(response)

	finding, found := findingWithTitle(result.Findings,
		"Total response time is critically slow: 25000 ms")
	require.True(t, found)
	require.Equal(t, types.SeverityCritical, finding.Severity)
}

func TestRunPerformanceLargeBodyIsWarning(t *testing.T) {
	response := performanceResponse(network.Timings{
		TTFBMS:  100,
		TotalMS: 500,
	}, 6*1024*1024)

	result := checks.RunPerformance(response)

	finding, found := findingWithTitle(result.Findings,
		"Response body is large: 6.0 MB")
	require.True(t, found)
	require.Equal(t, types.SeverityWarning, finding.Severity)
}

func TestRunPerformanceCriticallyLargeBodyIsCritical(t *testing.T) {
	response := performanceResponse(network.Timings{
		TTFBMS:  100,
		TotalMS: 800,
	}, 16*1024*1024)

	result := checks.RunPerformance(response)

	finding, found := findingWithTitle(result.Findings,
		"Response body is critically large: 16.0 MB")
	require.True(t, found)
	require.Equal(t, types.SeverityCritical, finding.Severity)
}

func TestRunPerformanceSlowDNSIsInfo(t *testing.T) {
	response := performanceResponse(network.Timings{
		DNSMS:   800,
		TTFBMS:  150,
		TotalMS: 1200,
	}, 1024)

	result := checks.RunPerformance(response)

	_, found := findingWithTitle(result.Findings, "DNS lookup took 800 ms")
	require.True(t, found)
}

func TestRunPerformanceSlowTLSIsInfo(t *testing.T) {
	response := performanceResponse(network.Timings{
		TLSMS:   1500,
		TTFBMS:  200,
		TotalMS: 2000,
	}, 1024)

	result := checks.RunPerformance(response)

	_, found := findingWithTitle(result.Findings, "TLS handshake took 1500 ms")
	require.True(t, found)
}

func TestRunPerformanceLowThroughputIsInfo(t *testing.T) {
	bodySize := 512 * 1024 // 512 KB
	downloadMS := int64(10000) // 10 seconds → ~51 KB/s

	response := performanceResponse(network.Timings{
		TTFBMS:     100,
		DownloadMS: downloadMS,
		TotalMS:    downloadMS + 200,
	}, bodySize)

	result := checks.RunPerformance(response)

	_, found := findingWithTitle(result.Findings, "Download throughput is low: 51 KB/s")
	require.True(t, found)
}
