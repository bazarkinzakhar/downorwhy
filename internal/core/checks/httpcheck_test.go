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

func newHTTPResponse(statusCode int, proto string) *network.Response {
	finalURL, err := url.Parse("https://example.com/")
	if err != nil {
		panic(err)
	}

	return &network.Response{
		FinalURL:        finalURL,
		StatusCode:      statusCode,
		Status:          http.StatusText(statusCode),
		Proto:           proto,
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Compressed:      true,
		ContentEncoding: "gzip",
		Timings: network.Timings{
			TotalMS: 123,
		},
	}
}

func findingWithTitle(findings []types.Finding, title string) (types.Finding, bool) {
	for _, finding := range findings {
		if finding.Title == title {
			return finding, true
		}
	}
	return types.Finding{}, false
}

func TestRunHTTPNilResponse(t *testing.T) {
	result := checks.RunHTTP(nil)

	require.Equal(t, types.CheckStatusError, result.Status)
	require.NotEmpty(t, result.Error)
	require.Empty(t, result.Findings)
}

func TestRunHTTPHealthyResponse(t *testing.T) {
	response := newHTTPResponse(http.StatusOK, "HTTP/2.0")

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
	require.Equal(t, http.StatusOK, result.Details["statusCode"])
	require.Equal(t, "HTTP/2.0", result.Details["protocol"])
}

func TestRunHTTPServerErrorIsCritical(t *testing.T) {
	response := newHTTPResponse(http.StatusBadGateway, "HTTP/2.0")

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, types.SeverityCritical, result.Findings[0].Severity)
	require.Equal(t, types.OwnerBackend, result.Findings[0].Owner)
	require.Contains(t, result.Findings[0].Title, "502")
}

func TestRunHTTPClientErrorIsWarning(t *testing.T) {
	response := newHTTPResponse(http.StatusNotFound, "HTTP/2.0")

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusWarn, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, types.SeverityWarning, result.Findings[0].Severity)
	require.Contains(t, result.Findings[0].Title, "404")
}

func TestRunHTTPUncompressedResponseIsInformational(t *testing.T) {
	response := newHTTPResponse(http.StatusOK, "HTTP/2.0")
	response.Compressed = false

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	_, found := findingWithTitle(result.Findings, "Response is not compressed")
	require.True(t, found)
}

func TestRunHTTPHTTP11IsInformational(t *testing.T) {
	response := newHTTPResponse(http.StatusOK, "HTTP/1.1")

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	finding, found := findingWithTitle(result.Findings, "HTTP/2 was not negotiated")
	require.True(t, found)
	require.Equal(t, types.OwnerDevOps, finding.Owner)
}

func TestRunHTTPTruncatedBodyIsWarning(t *testing.T) {
	response := newHTTPResponse(http.StatusOK, "HTTP/2.0")
	response.Body = make([]byte, 1024)
	response.BodyTruncated = true

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusWarn, result.Status)
	finding, found := findingWithTitle(result.Findings, "Response body exceeded the scan safety limit")
	require.True(t, found)
	require.Equal(t, types.SeverityWarning, finding.Severity)
	require.Equal(t, 1024, finding.Evidence["maxBodyBytes"])
}

func TestRunHTTPFinalRedirectIsInformational(t *testing.T) {
	response := newHTTPResponse(http.StatusPermanentRedirect, "HTTP/2.0")

	result := checks.RunHTTP(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	_, found := findingWithTitle(result.Findings, "Final response is HTTP 308")
	require.True(t, found)
}