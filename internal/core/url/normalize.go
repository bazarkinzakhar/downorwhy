// Package url normalises user-supplied URLs and enforces the SSRF policy that
// governs every outbound connection DownOrWhy makes.
package url

import (
	"fmt"
	"net"
	neturl "net/url"
	"sort"
	"strings"

	"golang.org/x/net/idna"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// RedactedValue replaces query parameter values in reports.
const RedactedValue = "REDACTED"

// Target is a normalised, syntactically valid HTTP(S) URL. Values of this type
// are only produced by Normalize, which guarantees an absolute URL with an
// http or https scheme and a non-empty ASCII host.
type Target struct {
	// URL is the normalised URL used for the actual request.
	URL *neturl.URL
	// Host is the ASCII (punycode) host without a port and without brackets,
	// even for IPv6 literals.
	Host string
	// UnicodeHost is the display form of Host; equal to Host for ASCII names.
	UnicodeHost string
	// Port is the effective port, explicit or scheme default.
	Port string
	// Scheme is "http" or "https".
	Scheme string
	// SchemeAssumed is true when the input had no scheme and https was added.
	SchemeAssumed bool
}

// String returns the normalised URL as text.
func (t Target) String() string { return t.URL.String() }

// HostPort returns host:port suitable for net.Dial. IPv6 literals are
// bracketed as net.Dial requires.
func (t Target) HostPort() string { return net.JoinHostPort(t.Host, t.Port) }

// IsHTTPS reports whether the target uses TLS.
func (t Target) IsHTTPS() bool { return t.Scheme == "https" }

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(true),
)

// Normalize parses raw user input into a Target.
//
// It trims whitespace, assumes https when no scheme is present, lowercases the
// scheme and host, converts internationalised host names to punycode, drops
// the default port, ensures a non-empty path, and removes the fragment, which
// is never transmitted and may carry sensitive data.
func Normalize(raw string) (Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Target{}, fmt.Errorf("%w: empty input", types.ErrInvalidURL)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return Target{}, fmt.Errorf("%w: contains whitespace", types.ErrInvalidURL)
	}

	schemeAssumed := false
	if !hasScheme(trimmed) {
		trimmed = "https://" + trimmed
		schemeAssumed = true
	}

	u, err := neturl.Parse(trimmed)
	if err != nil {
		return Target{}, fmt.Errorf("%w: %s", types.ErrInvalidURL, err)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("%w: unsupported scheme %q", types.ErrInvalidURL, u.Scheme)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("%w: credentials in URL are not accepted", types.ErrInvalidURL)
	}
	if u.Opaque != "" {
		return Target{}, fmt.Errorf("%w: opaque URL", types.ErrInvalidURL)
	}

	unicodeHost := strings.ToLower(u.Hostname())
	if unicodeHost == "" {
		return Target{}, fmt.Errorf("%w: missing host", types.ErrInvalidURL)
	}

	asciiHost := unicodeHost
	if !isIPLiteral(unicodeHost) {
		asciiHost, err = idnaProfile.ToASCII(unicodeHost)
		if err != nil {
			return Target{}, fmt.Errorf("%w: invalid host name %q: %s", types.ErrInvalidURL, unicodeHost, err)
		}
		if !isPlausibleHostname(asciiHost) {
			return Target{}, fmt.Errorf("%w: invalid host name %q", types.ErrInvalidURL, asciiHost)
		}
	}

	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	} else if !isNumericPort(port) {
		return Target{}, fmt.Errorf("%w: invalid port %q", types.ErrInvalidURL, port)
	}

	// Rebuild the authority. IPv6 literals must stay bracketed inside the URL
	// even when the default port is omitted.
	if port == defaultPort(u.Scheme) {
		if strings.Contains(asciiHost, ":") {
			u.Host = "[" + asciiHost + "]"
		} else {
			u.Host = asciiHost
		}
	} else {
		u.Host = net.JoinHostPort(asciiHost, port)
	}

	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	u.RawFragment = ""

	return Target{
		URL:           u,
		Host:          asciiHost,
		UnicodeHost:   unicodeHost,
		Port:          port,
		Scheme:        u.Scheme,
		SchemeAssumed: schemeAssumed,
	}, nil
}

// Redact returns u as a string with every query parameter value replaced by
// RedactedValue. Parameter names are preserved because they are
// diagnostically useful and are not themselves secrets; values frequently
// carry tokens. Keys are sorted so redacted output is deterministic.
func Redact(u *neturl.URL) string {
	if u == nil {
		return ""
	}
	if u.RawQuery == "" {
		return u.String()
	}

	clone := *u
	values, err := neturl.ParseQuery(u.RawQuery)
	if err != nil {
		// An unparseable query string is dropped entirely rather than leaked.
		clone.RawQuery = RedactedValue
		return clone.String()
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	redacted := make(neturl.Values, len(values))
	for _, k := range keys {
		for range values[k] {
			redacted.Add(k, RedactedValue)
		}
	}
	clone.RawQuery = redacted.Encode()

	return clone.String()
}

// Display returns the report-facing form of u, redacted when redact is true.
func Display(u *neturl.URL, redact bool) string {
	if u == nil {
		return ""
	}
	if redact {
		return Redact(u)
	}
	return u.String()
}

func hasScheme(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	for _, r := range s[:i] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '+', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

func isNumericPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n > 0 && n <= 65535
}

func isIPLiteral(host string) bool {
	return strings.Count(host, ":") >= 2 || isDottedQuad(host)
}

func isDottedQuad(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isPlausibleHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}
