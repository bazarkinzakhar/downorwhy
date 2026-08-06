package checks

import (
	"fmt"
	neturl "net/url"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RunRedirects evaluates the redirect chain captured by network.Client.
//
// The HTTP client already blocks unsafe redirect destinations before it follows
// them. This check repeats that validation against recorded locations so a
// report can explain why a redirect was rejected or why a chain is risky.
func RunRedirects(
	input dowurl.Target,
	response *network.Response,
	policy dowurl.Policy,
) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckRedirects)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusSkipped
		result.Summary = "redirects were not checked because no HTTP response was available"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	result.Set("hopCount", len(response.Hops))
	result.Set("hops", response.Hops)

	if len(response.Hops) == 0 {
		result.Summary = "no redirects observed"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	seen := map[string]int{}
	currentURL := input.URL
	seen[canonicalURL(currentURL)] = 0

	for index, hop := range response.Hops {
		hopURL, err := neturl.Parse(hop.URL)
		if err != nil {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerRedirect,
				Title:    "Redirect chain contains an invalid source URL",
				Description: "A recorded redirect source URL could not be parsed. " +
					"This may indicate a malformed upstream response or an unexpected client state.",
				Evidence: map[string]interface{}{
					"hop": index + 1,
					"url": hop.URL,
				},
				Owner: types.OwnerDevOps,
			})
			continue
		}

		nextURL, err := hopURL.Parse(hop.Location)
		if err != nil {
			result.AddFinding(types.Finding{
				Severity: types.SeverityCritical,
				Layer:    types.LayerRedirect,
				Title:    "Redirect location is malformed",
				Description: "The server returned a Location header that could not be parsed as a URL. " +
					"Browsers and clients may handle this inconsistently or fail the request.",
				Evidence: map[string]interface{}{
					"hop":      index + 1,
					"location": hop.Location,
				},
				Owner: types.OwnerBackend,
			})
			continue
		}

		if nextURL.Scheme == "" {
			nextURL.Scheme = currentURL.Scheme
		}
		if nextURL.Host == "" {
			nextURL.Host = currentURL.Host
		}

		nextTarget, normalizeErr := dowurl.Normalize(nextURL.String())
		if normalizeErr != nil {
			result.AddFinding(types.Finding{
				Severity: types.SeverityCritical,
				Layer:    types.LayerRedirect,
				Title:    "Redirect target is not a valid public HTTP URL",
				Description: "The server redirects clients to a malformed or unsupported URL. " +
					"This can make the destination unreachable for normal users.",
				Evidence: map[string]interface{}{
					"hop":      index + 1,
					"location": hop.Location,
					"error":    normalizeErr.Error(),
				},
				Owner: types.OwnerBackend,
			})
			continue
		}

		if safetyErr := policy.CheckRedirect(nextTarget); safetyErr != nil {
			result.AddFinding(types.Finding{
				Severity: types.SeverityCritical,
				Layer:    types.LayerSecurity,
				Title:    "Redirect points to an unsafe network target",
				Description: "The server attempted to redirect the client to a loopback, private, " +
					"link-local, metadata, multicast, reserved, or otherwise non-public address. " +
					"DownOrWhy refused to follow this redirect to prevent server-side request forgery.",
				Evidence: map[string]interface{}{
					"hop":      index + 1,
					"location": hop.Location,
					"target":   nextTarget.String(),
					"error":    safetyErr.Error(),
				},
				Owner: types.OwnerSecurity,
			})
			continue
		}

		nextCanonical := canonicalURL(nextTarget.URL)
		if firstHop, exists := seen[nextCanonical]; exists {
			result.AddFinding(types.Finding{
				Severity: types.SeverityCritical,
				Layer:    types.LayerRedirect,
				Title:    "Redirect loop detected",
				Description: "The redirect chain returns to a URL that was already visited. " +
					"Users will eventually receive a browser error instead of the requested page.",
				Evidence: map[string]interface{}{
					"firstSeenAtHop": firstHop,
					"repeatedAtHop":  index + 1,
					"url":            nextTarget.String(),
				},
				Owner: types.OwnerBackend,
			})
		} else {
			seen[nextCanonical] = index + 1
		}

		if currentURL.Scheme == "https" && nextTarget.Scheme == "http" {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerRedirect,
				Title:    "Redirect downgrades HTTPS to HTTP",
				Description: "The redirect sends clients from an encrypted HTTPS URL to plaintext HTTP. " +
					"Traffic can be observed or modified in transit after the downgrade.",
				Evidence: map[string]interface{}{
					"from": currentURL.String(),
					"to":   nextTarget.String(),
				},
				Owner: types.OwnerDevOps,
			})
		}

		if isWWWTransition(currentURL.Hostname(), nextTarget.Host) {
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerRedirect,
				Title:    "Redirect changes the www host form",
				Description: "The site redirects between the www and non-www host forms. " +
					"This is usually normal canonicalization; ensure all public entry points consistently " +
					"redirect to the chosen canonical host in one hop.",
				Evidence: map[string]interface{}{
					"fromHost": currentURL.Hostname(),
					"toHost":   nextTarget.Host,
				},
				Owner: types.OwnerDevOps,
			})
		}

		currentURL = nextTarget.URL
	}

	result.Summary = fmt.Sprintf("followed %d redirect hop(s)", len(response.Hops))
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

func canonicalURL(u *neturl.URL) string {
	clone := *u
	clone.Fragment = ""
	clone.RawFragment = ""
	clone.Host = strings.ToLower(clone.Host)
	clone.Scheme = strings.ToLower(clone.Scheme)

	return clone.String()
}

func isWWWTransition(fromHost, toHost string) bool {
	fromHost = strings.ToLower(strings.TrimSuffix(fromHost, "."))
	toHost = strings.ToLower(strings.TrimSuffix(toHost, "."))

	if fromHost == toHost {
		return false
	}

	if strings.TrimPrefix(fromHost, "www.") == toHost && strings.HasPrefix(fromHost, "www.") {
		return true
	}

	return strings.TrimPrefix(toHost, "www.") == fromHost && strings.HasPrefix(toHost, "www.")
}
