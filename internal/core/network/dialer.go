package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/types"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
)

// IPLookuper resolves a host name to IP addresses. *net.Resolver satisfies
// this interface through LookupNetIP; tests inject a stub.
type IPLookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialStats reports the phase timings measured by SafeDialer for the most
// recent successful connection. A value of -1 means the phase did not occur,
// which happens for DNS when the host was already an IP literal.
type DialStats struct {
	DNSMS     int64
	ConnectMS int64
}

// SafeDialer resolves and validates every candidate address immediately
// before connecting to it. Validation happens at dial time, not earlier, so a
// DNS answer that changes between an earlier check and the actual connection
// cannot be used to bypass the SSRF policy (DNS rebinding).
//
// A SafeDialer is shared by the HTTP client and the TLS client so the two
// never diverge on what counts as a safe address.
type SafeDialer struct {
	policy   dowurl.Policy
	resolver IPLookuper
	timeout  time.Duration

	mu     sync.Mutex
	dialed []netip.Addr
	stats  DialStats
}

// NewSafeDialer builds a dialer bound by policy and timeout. A nil resolver
// falls back to net.DefaultResolver.
func NewSafeDialer(policy dowurl.Policy, resolver IPLookuper, timeout time.Duration) *SafeDialer {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &SafeDialer{
		policy:   policy,
		resolver: resolver,
		timeout:  timeout,
		stats:    DialStats{DNSMS: -1, ConnectMS: -1},
	}
}

// DialedAddrs returns every address this dialer has successfully connected
// to, in connection order. Used to report the true peer for security checks.
func (d *SafeDialer) DialedAddrs() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]netip.Addr, len(d.dialed))
	copy(out, d.dialed)

	return out
}

// Stats returns the timings of the most recent successful connection.
func (d *SafeDialer) Stats() DialStats {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.stats
}

// DialContext matches the signature required by http.Transport.DialContext
// and is also used directly by the TLS client for raw handshakes.
func (d *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed dial address %q", types.ErrInvalidURL, address)
	}

	dnsStart := time.Now()
	addrs, literal, err := d.resolveAddrs(ctx, host)
	if err != nil {
		return nil, err
	}

	dnsMS := int64(-1)
	if !literal {
		dnsMS = time.Since(dnsStart).Milliseconds()
	}

	dialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 15 * time.Second}

	var lastErr error
	for _, addr := range addrs {
		if policyErr := d.policy.CheckAddr(addr); policyErr != nil {
			lastErr = policyErr
			continue
		}

		connectStart := time.Now()
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr != nil {
			lastErr = dialErr
			continue
		}

		d.mu.Lock()
		d.dialed = append(d.dialed, addr)
		d.stats = DialStats{DNSMS: dnsMS, ConnectMS: time.Since(connectStart).Milliseconds()}
		d.mu.Unlock()

		return conn, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no usable address for %s", types.ErrUnreachable, host)
	}

	return nil, lastErr
}

// resolveAddrs returns the candidate addresses for host. The boolean result
// reports whether host was already an IP literal, in which case no DNS query
// was performed and DNS timing is not meaningful.
func (d *SafeDialer) resolveAddrs(ctx context.Context, host string) ([]netip.Addr, bool, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, true, nil
	}

	ips, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, false, fmt.Errorf("%w: cannot resolve %s: %s", types.ErrUnreachable, host, err)
	}
	if len(ips) == 0 {
		return nil, false, fmt.Errorf("%w: no addresses for %s", types.ErrUnreachable, host)
	}

	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		out = append(out, ip)
	}

	return out, false, nil
}
