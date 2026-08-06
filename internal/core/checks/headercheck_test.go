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

func headersResponse(scheme string, headers http.Header) *network.Response {
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
		FinalURL: finalURL,
		Header:   normalized,
	}
}

func hasHeaderFinding(findings []types.Finding, title string) (types.Finding, bool) {
	for _, finding := range findings {
		if finding.Title == title {
			return finding, true
		}
	}
	return types.Finding{}, false
}

func TestRunHeadersNilResponseIsSkipped(t *testing.T) {
	result := checks.RunHeaders(nil)

	require.Equal(t, types.CheckStatusSkipped, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunHeadersSecureBaselinePasses(t *testing.T) {
	response := headersResponse("https", http.Header{
		"Strict-Transport-Security":       []string{"max-age=31536000; includeSubDomains"},
		"Content-Security-Policy":         []string{"default-src 'self'; frame-ancestors 'none'"},
		"X-Content-Type-Options":          []string{"nosniff"},
		"Referrer-Policy":                 []string{"strict-origin-when-cross-origin"},
		"X-Frame-Options":                 []string{"DENY"},
		"Access-Control-Allow-Origin":     []string{"https://app.example.com"},
		"Access-Control-Allow-Credentials": []string{"true"},
	})

	result := checks.RunHeaders(response)

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunHeadersMissingSecurityHeaders(t *testing.T) {
	response := headersResponse("https", http.Header{})

	result := checks.RunHeaders(response)

	require.Equal(t, types.CheckStatusWarn, result.Status)

	expectedTitles := []string{
		"HSTS header is missing",
		"Content-Security-Policy header is missing",
		"X-Content-Type-Options: nosniff is missing",
		"Referrer-Policy header is missing",
		"Clickjacking protection header is missing",
	}

	for _, title := range expectedTitles {
		_, found := hasHeaderFinding(result.Findings, title)
		require.True(t, found, "missing expected finding %q", title)
	}
}

func TestRunHeadersDoesNotRequireHSTSOverHTTP(t *testing.T) {
	response := headersResponse("http", http.Header{
		"Content-Security-Policy": []string{"default-src 'self'"},
		"X-Content-Type-Options":  []string{"nosniff"},
		"Referrer-Policy":         []string{"same-origin"},
		"X-Frame-Options":         []string{"DENY"},
	})

	result := checks.RunHeaders(response)

	_, found := hasHeaderFinding(result.Findings, "HSTS header is missing")
	require.False(t, found)
}

func TestRunHeadersCORSWildcardWithCredentialsIsCritical(t *testing.T) {
	response := headersResponse("https", http.Header{
		"Access-Control-Allow-Origin":      []string{"*"},
		"Access-Control-Allow-Credentials": []string{"true"},
	})

	result := checks.RunHeaders(response)

	require.Equal(t, types.CheckStatusFail, result.Status)

	finding, found := hasHeaderFinding(result.Findings, "CORS allows wildcard origins with credentials")
	require.True(t, found)
	require.Equal(t, types.SeverityCritical, finding.Severity)
	require.Equal(t, types.OwnerSecurity, finding.Owner)
}

func TestRunHeadersCORSWildcardWithoutCredentialsIsInfo(t *testing.T) {
	response := headersResponse("https", http.Header{
		"Access-Control-Allow-Origin": []string{"*"},
	})

	result := checks.RunHeaders(response)

	finding, found := hasHeaderFinding(result.Findings, "CORS allows all origins")
	require.True(t, found)
	require.Equal(t, types.SeverityInfo, finding.Severity)
}

func TestRunHeadersCookieSecurityAttributes(t *testing.T) {
	response := headersResponse("https", http.Header{
		"Set-Cookie": []string{
			"session=opaque",
		},
	})

	result := checks.RunHeaders(response)

	expectedTitles := []string{
		"Cookie is missing the Secure attribute",
		"Cookie is missing the HttpOnly attribute",
		"Cookie does not declare SameSite",
	}

	for _, title := range expectedTitles {
		finding, found := hasHeaderFinding(result.Findings, title)
		require.True(t, found, "missing expected finding %q", title)
		require.Equal(t, "session", finding.Evidence["cookie"])
	}
}

func TestRunHeadersCookieWithAllAttributesDoesNotProduceCookieFindings(t *testing.T) {
	response := headersResponse("https", http.Header{
		"Set-Cookie": []string{
			"session=opaque; Path=/; Secure; HttpOnly; SameSite=Strict",
		},
	})

	result := checks.RunHeaders(response)

	for _, title := range []string{
		"Cookie is missing the Secure attribute",
		"Cookie is missing the HttpOnly attribute",
		"Cookie does not declare SameSite",
	} {
		_, found := hasHeaderFinding(result.Findings, title)
		require.False(t, found, "unexpected finding %q", title)
	}
}