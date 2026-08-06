package checks

import (
	"net/http"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RunHeaders checks the security-relevant HTTP headers and cookie attributes
// exposed by the single response collected during scanning.
func RunHeaders(response *network.Response) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckHeaders)
	result.Status = types.CheckStatusPass

	if response == nil {
		result.Status = types.CheckStatusSkipped
		result.Summary = "headers were not checked because no HTTP response was available"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	headers := response.Header
	result.Set("strictTransportSecurity", headers.Get("Strict-Transport-Security"))
	result.Set("contentSecurityPolicy", headers.Get("Content-Security-Policy"))
	result.Set("xContentTypeOptions", headers.Get("X-Content-Type-Options"))
	result.Set("xFrameOptions", headers.Get("X-Frame-Options"))
	result.Set("referrerPolicy", headers.Get("Referrer-Policy"))
	result.Set("accessControlAllowOrigin", headers.Get("Access-Control-Allow-Origin"))
	result.Set("accessControlAllowCredentials", headers.Get("Access-Control-Allow-Credentials"))
	result.Set("setCookieCount", len(headers.Values("Set-Cookie")))

	if response.FinalURL != nil && response.FinalURL.Scheme == "https" &&
		strings.TrimSpace(headers.Get("Strict-Transport-Security")) == "" {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHeaders,
			Title:    "HSTS header is missing",
			Description: "The HTTPS response does not include Strict-Transport-Security. " +
				"Without HSTS, users who type or follow an HTTP URL may be exposed to a first-request " +
				"downgrade before the browser upgrades them to HTTPS.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerSecurity,
		})
	}

	if strings.TrimSpace(headers.Get("Content-Security-Policy")) == "" {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHeaders,
			Title:    "Content-Security-Policy header is missing",
			Description: "The response does not define a Content Security Policy. CSP limits the impact " +
				"of cross-site scripting and accidental third-party content injection.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerSecurity,
		})
	}

	if !strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff") {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHeaders,
			Title:    "X-Content-Type-Options: nosniff is missing",
			Description: "Browsers may MIME-sniff resources when this header is absent. " +
				"Set X-Content-Type-Options to nosniff for responses served to browsers.",
			Evidence: map[string]interface{}{
				"received": headers.Get("X-Content-Type-Options"),
			},
			Owner: types.OwnerSecurity,
		})
	}

	if strings.TrimSpace(headers.Get("Referrer-Policy")) == "" {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerHeaders,
			Title:    "Referrer-Policy header is missing",
			Description: "The response does not explicitly control which URL information browsers send " +
				"to subsequent destinations in the Referer header.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerSecurity,
		})
	}

	if strings.TrimSpace(headers.Get("X-Frame-Options")) == "" &&
		!strings.Contains(strings.ToLower(headers.Get("Content-Security-Policy")), "frame-ancestors") {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerHeaders,
			Title:    "Clickjacking protection header is missing",
			Description: "Neither X-Frame-Options nor a CSP frame-ancestors directive was found. " +
				"Other sites may be able to embed this page in a frame and deceive users into clicking it.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerSecurity,
		})
	}

	checkCORS(&result, headers)
	checkCookies(&result, headers)

	result.Summary = "evaluated HTTP security headers and cookies"
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

func checkCORS(result *types.CheckResult, headers http.Header) {
	allowOrigin := strings.TrimSpace(headers.Get("Access-Control-Allow-Origin"))
	allowCredentials := strings.EqualFold(
		strings.TrimSpace(headers.Get("Access-Control-Allow-Credentials")),
		"true",
	)

	if allowOrigin == "*" && allowCredentials {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerSecurity,
			Title:    "CORS allows wildcard origins with credentials",
			Description: "The response declares both Access-Control-Allow-Origin: * and " +
				"Access-Control-Allow-Credentials: true. Browsers reject this exact combination, " +
				"but it signals an unsafe or confused cross-origin policy that should be corrected.",
			Evidence: map[string]interface{}{
				"accessControlAllowOrigin":      allowOrigin,
				"accessControlAllowCredentials": true,
			},
			Owner: types.OwnerSecurity,
		})
		return
	}

	if allowOrigin == "*" {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerSecurity,
			Title:    "CORS allows all origins",
			Description: "The response is readable by browser JavaScript from any origin. " +
				"This is appropriate only for intentionally public, unauthenticated resources.",
			Evidence: map[string]interface{}{
				"accessControlAllowOrigin": allowOrigin,
			},
			Owner: types.OwnerSecurity,
		})
	}
}

func checkCookies(result *types.CheckResult, headers http.Header) {
	for _, rawCookie := range headers.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(rawCookie)
		if err != nil {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerHeaders,
				Title:    "Server sent an unparsable Set-Cookie header",
				Description: "A Set-Cookie header could not be parsed using the standard HTTP cookie parser. " +
					"Browsers may interpret malformed cookie attributes differently.",
				Evidence: map[string]interface{}{
					"error": err.Error(),
				},
				Owner: types.OwnerBackend,
			})
			continue
		}

		if !cookie.Secure {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerSecurity,
				Title:    "Cookie is missing the Secure attribute",
				Description: "The cookie can be sent over plaintext HTTP if the browser reaches an HTTP " +
					"version of this host. Session and authentication cookies should always be Secure.",
				Evidence: map[string]interface{}{
					"cookie": cookie.Name,
				},
				Owner: types.OwnerSecurity,
			})
		}

		if !cookie.HttpOnly {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerSecurity,
				Title:    "Cookie is missing the HttpOnly attribute",
				Description: "JavaScript running in the page can read this cookie. " +
					"Authentication and session cookies should normally be marked HttpOnly.",
				Evidence: map[string]interface{}{
					"cookie": cookie.Name,
				},
				Owner: types.OwnerSecurity,
			})
		}

		if cookie.SameSite == http.SameSiteDefaultMode {
			result.AddFinding(types.Finding{
				Severity: types.SeverityInfo,
				Layer:    types.LayerSecurity,
				Title:    "Cookie does not declare SameSite",
				Description: "The cookie relies on browser default SameSite behaviour. " +
					"Declare SameSite=Lax, Strict, or None explicitly after confirming the required " +
					"cross-site login and embedded-content flows.",
				Evidence: map[string]interface{}{
					"cookie": cookie.Name,
				},
				Owner: types.OwnerSecurity,
			})
		}
	}
}
