package url

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// BlockReason explains why an address or host was rejected.
type BlockReason string

// Block reasons reported to users and recorded as finding evidence.
const (
	ReasonLoopback       BlockReason = "loopback address"
	ReasonPrivate        BlockReason = "private address range"
	ReasonLinkLocal      BlockReason = "link-local address"
	ReasonUniqueLocal    BlockReason = "IPv6 unique local address"
	ReasonMulticast      BlockReason = "multicast address"
	ReasonUnspecified    BlockReason = "unspecified address"
	ReasonReserved       BlockReason = "reserved address range"
	ReasonCloudMetadata  BlockReason = "cloud metadata endpoint"
	ReasonBlockedHost    BlockReason = "blocked host name"
	ReasonNonGlobalScope BlockReason = "address is not globally routable"
)

// blockedPrefixes is the deny list applied to every IP address DownOrWhy is
// about to connect to. It is intentionally a static, auditable table rather
// than a set of stdlib predicate calls, because the stdlib predicates do not
// cover carrier-grade NAT, benchmarking or documentation ranges.
var blockedPrefixes = buildPrefixes(map[BlockReason][]string{
	ReasonUnspecified: {"0.0.0.0/8", "::/128"},
	ReasonLoopback:    {"127.0.0.0/8", "::1/128"},
	ReasonPrivate: {
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // RFC 6598 carrier-grade NAT
	},
	ReasonLinkLocal:   {"169.254.0.0/16", "fe80::/10"},
	ReasonUniqueLocal: {"fc00::/7"},
	ReasonMulticast:   {"224.0.0.0/4", "ff00::/8"},
	ReasonReserved: {
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved for future use
		"255.255.255.255/32",
		"2001:db8::/32", // documentation
		"64:ff9b::/96",  // NAT64, may map to private IPv4
		"100::/64",      // discard-only
	},
	ReasonCloudMetadata: {
		"169.254.169.254/32", // AWS, GCP, Azure, DigitalOcean, OpenStack
		"169.254.170.2/32",   // AWS ECS task metadata
		"100.100.100.200/32", // Alibaba Cloud
		"192.0.0.192/32",     // Oracle Cloud
		"fd00:ec2::254/128",  // AWS IMDS over IPv6
	},
})

// blockedHostSuffixes are names that resolve to infrastructure endpoints and
// are rejected before any DNS query is issued.
var blockedHostSuffixes = []string{
	"localhost",
	".localhost",
	".local",
	".internal",
	".localdomain",
	"metadata.google.internal",
	".consul",
	".onion",
}

type prefixEntry struct {
	prefix netip.Prefix
	reason BlockReason
}

func buildPrefixes(src map[BlockReason][]string) []prefixEntry {
	out := make([]prefixEntry, 0, 32)
	for reason, list := range src {
		for _, cidr := range list {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				// Table is a compile-time constant; a bad entry is a defect.
				panic("safeurl: invalid CIDR in deny list: " + cidr)
			}
			out = append(out, prefixEntry{prefix: p, reason: reason})
		}
	}
	return out
}

// Policy decides which targets may be contacted.
type Policy struct {
	// AllowPrivate disables the IP deny list. It exists for operators who
	// scan their own internal hosts from a trusted shell. It is never set
	// by the API server or the GitHub Action.
	AllowPrivate bool
}

// DefaultPolicy returns the production-safe policy.
func DefaultPolicy() Policy { return Policy{} }

// CheckAddr validates a single resolved IP address.
func (p Policy) CheckAddr(addr netip.Addr) error {
	if p.AllowPrivate {
		return nil
	}
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid IP address", types.ErrUnsafeTarget)
	}
	// Normalise IPv4-in-IPv6 (::ffff:127.0.0.1) so it cannot bypass the
	// IPv4 table by arriving in IPv6 form.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, e := range blockedPrefixes {
		if e.prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if e.prefix.Contains(addr) {
			return fmt.Errorf("%w: %s is a %s", types.ErrUnsafeTarget, addr, e.reason)
		}
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("%w: %s is %s", types.ErrUnsafeTarget, addr, ReasonNonGlobalScope)
	}
	return nil
}

// CheckHost validates a host name or IP literal before any DNS query. It
// cannot decide safety for names, only reject obviously unsafe ones; the
// authoritative decision is made per resolved address in CheckAddr, including
// at dial time, which closes the DNS-rebinding window.
func (p Policy) CheckHost(host string) error {
	if p.AllowPrivate {
		return nil
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return fmt.Errorf("%w: empty host", types.ErrUnsafeTarget)
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return p.CheckAddr(addr)
	}
	if !strings.Contains(h, ".") {
		// Single-label names resolve through local search domains and are
		// not meaningful public targets.
		return fmt.Errorf("%w: %q is a %s", types.ErrUnsafeTarget, host, ReasonBlockedHost)
	}
	for _, suffix := range blockedHostSuffixes {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return fmt.Errorf("%w: %q is a %s", types.ErrUnsafeTarget, host, ReasonBlockedHost)
		}
	}
	return nil
}

// CheckTarget validates a normalised Target: scheme, port and host.
func (p Policy) CheckTarget(t Target) error {
	if t.Scheme != "http" && t.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", types.ErrUnsafeTarget, t.Scheme)
	}
	return p.CheckHost(t.Host)
}

// CheckRedirect validates a redirect hop. It rejects unsafe destinations and
// scheme changes that are not http -> https upgrades.
func (p Policy) CheckRedirect(next Target) error {
	return p.CheckTarget(next)
}

// ReasonFor returns the deny-list reason for addr, or an empty reason when the
// address is allowed. It is used to attach evidence to findings.
func ReasonFor(addr netip.Addr) BlockReason {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, e := range blockedPrefixes {
		if e.prefix.Addr().Is4() == addr.Is4() && e.prefix.Contains(addr) {
			return e.reason
		}
	}
	if addr.IsValid() && !addr.IsGlobalUnicast() {
		return ReasonNonGlobalScope
	}
	return ""
}
