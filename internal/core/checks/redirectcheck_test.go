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

func redirectInputTarget(t *testing.T, rawURL string) dowurl.Target {
	t.Helper()

	target, err := dowurl.Normalize(rawURL)
	require.NoError(t, err)

	return target
}

func redirectResponse(hops ...network.Hop) *network.Response {
	finalURL, err := url.Parse("https://example.com/final")
	if err != nil {
		panic(err)
	}

	return &network.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		FinalURL:   finalURL,
		Hops:       hops,
	}
}

func TestRunRedirectsNoResponseIsSkipped(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/")

	result := checks.RunRedirects(input, nil, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusSkipped, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunRedirectsNoRedirectsIsHealthy(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/")

	result := checks.RunRedirects(input, redirectResponse(), dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
	require.Equal(t, 0, result.Details["hopCount"])
}

func TestRunRedirectsDetectsLoop(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/a")
	response := redirectResponse(
		network.Hop{
			URL:        "https://example.com/a",
			StatusCode: http.StatusFound,
			Location:   "/b",
		},
		network.Hop{
			URL:        "https://example.com/b",
			StatusCode: http.StatusFound,
			Location:   "/a",
		},
	)

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusFail, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "Redirect loop detected" {
			found = true
			require.Equal(t, types.SeverityCritical, finding.Severity)
			require.Equal(t, types.OwnerBackend, finding.Owner)
		}
	}
	require.True(t, found)
}

func TestRunRedirectsDetectsHTTPSDowngrade(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/")
	response := redirectResponse(network.Hop{
		URL:        "https://example.com/",
		StatusCode: http.StatusMovedPermanently,
		Location:   "http://example.com/",
	})

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusWarn, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "Redirect downgrades HTTPS to HTTP" {
			found = true
			require.Equal(t, types.SeverityWarning, finding.Severity)
			require.Equal(t, types.OwnerDevOps, finding.Owner)
		}
	}
	require.True(t, found)
}

func TestRunRedirectsDetectsUnsafeTarget(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/")
	response := redirectResponse(network.Hop{
		URL:        "https://example.com/",
		StatusCode: http.StatusFound,
		Location:   "http://169.254.169.254/latest/meta-data/",
	})

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusFail, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "Redirect points to an unsafe network target" {
			found = true
			require.Equal(t, types.SeverityCritical, finding.Severity)
			require.Equal(t, types.LayerSecurity, finding.Layer)
			require.Equal(t, types.OwnerSecurity, finding.Owner)
		}
	}
	require.True(t, found)
}

func TestRunRedirectsRecognizesRelativeLocation(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/start")
	response := redirectResponse(network.Hop{
		URL:        "https://example.com/start",
		StatusCode: http.StatusFound,
		Location:   "/next",
	})

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunRedirectsRecognizesWWWCanonicalization(t *testing.T) {
	input := redirectInputTarget(t, "https://www.example.com/")
	response := redirectResponse(network.Hop{
		URL:        "https://www.example.com/",
		StatusCode: http.StatusMovedPermanently,
		Location:   "https://example.com/",
	})

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusPass, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "Redirect changes the www host form" {
			found = true
			require.Equal(t, types.SeverityInfo, finding.Severity)
		}
	}
	require.True(t, found)
}

func TestRunRedirectsMalformedLocationIsCritical(t *testing.T) {
	input := redirectInputTarget(t, "https://example.com/")
	response := redirectResponse(network.Hop{
		URL:        "https://example.com/",
		StatusCode: http.StatusFound,
		Location:   "http://[invalid-host",
	})

	result := checks.RunRedirects(input, response, dowurl.DefaultPolicy())

	require.Equal(t, types.CheckStatusFail, result.Status)

	found := false
	for _, finding := range result.Findings {
		if finding.Title == "Redirect location is malformed" {
			found = true
		}
	}
	require.True(t, found)
}
