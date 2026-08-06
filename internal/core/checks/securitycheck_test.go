package checks_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/checks"
	"github.com/downorwhy/downorwhy/internal/core/network"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func securityResponse(scheme string, headers http.Header, body string) *network.Response {
	finalURL, err := url.Parse(scheme + "://example.com/")
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
		Body:       []byte(body),
	}
}

func TestRunSecurityNilResponseIsSkipped(t *testing.T) {
	result := checks.RunSecurity(nil, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusSkipped, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunSecurityServerDisclosureIsInfo(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
		"Server":       []string{"Apache/2.4.59 (Ubuntu)"},
	}, "<html></html>")

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	_, found := findingWithTitle(result.Findings,
		"Server header discloses software and version")
	require.True(t, found)
}

func TestRunSecurityXPoweredByIsInfo(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"text/html"},
		"X-Powered-By": []string{"PHP/8.2.0"},
	}, "")

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	_, found := findingWithTitle(result.Findings,
		"X-Powered-By header discloses application framework")
	require.True(t, found)
}

func TestRunSecurityAspNetVersionIsInfo(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type":     []string{"text/html"},
		"X-AspNet-Version": []string{"4.0.30319"},
	}, "")

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	_, found := findingWithTitle(result.Findings,
		"X-AspNet-Version header discloses runtime version")
	require.True(t, found)
}

func TestRunSecurityMixedContentIsCritical(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}, `<html><body><img src="http://example.com/photo.jpg"></body></html>`)

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	finding, found := findingWithTitle(result.Findings,
		"HTTPS page references HTTP resources (mixed content)")
	require.True(t, found)
	require.Equal(t, types.SeverityCritical, finding.Severity)
	require.Equal(t, types.OwnerFrontend, finding.Owner)
	require.Equal(t, 1, finding.Evidence["estimatedHttpReferences"])
}

func TestRunSecurityMixedContentNotCheckedOverPlaintextHTTP(t *testing.T) {
	response := securityResponse("http", http.Header{
		"Content-Type": []string{"text/html"},
	}, `<img src="http://example.com/photo.jpg">`)

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	for _, finding := range result.Findings {
		require.NotEqual(t, "HTTPS page references HTTP resources (mixed content)", finding.Title)
	}
}

func TestRunSecurityMixedContentNotCheckedOnJSON(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"image": "http://example.com/photo.jpg"}`)

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	for _, finding := range result.Findings {
		require.NotEqual(t, "HTTPS page references HTTP resources (mixed content)", finding.Title)
	}
}

func TestRunSecurityDirectoryListingIsWarning(t *testing.T) {
	body := `<html><head><title>Index of /downloads</title></head><body><p>placeholder</p></body></html>`
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"text/html"},
	}, body)

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	_, found := findingWithTitle(result.Findings, "Directory listing may be enabled")
	require.True(t, found)
}

func TestRunSecurityCleanResponsePasses(t *testing.T) {
	response := securityResponse("https", http.Header{
		"Content-Type": []string{"text/html"},
	}, "<html><head><title>Home</title></head><body></body></html>")

	result := checks.RunSecurity(response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}