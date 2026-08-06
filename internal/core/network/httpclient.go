// Package network provides the HTTP, DNS and TLS clients used by checks. All
// outbound connections in DownOrWhy originate here and are subject to the SSRF
// policy in internal/core/url.
package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// Timings holds the phase breakdown of a single HTTP transaction, measured
// with httptrace. Values are milliseconds; -1 means the phase did not occur
// (for example TLS on a plaintext request).
type Timings struct {
	DNSMS      int64 `json:"dnsMs"`
	ConnectMS  int64 `json:"connectMs"`
	TLSMS      int64 `json:"tlsMs"`
	TTFBMS     int64 `json:"ttfbMs"`
	DownloadMS int64 `json:"downloadMs"`
	TotalMS    int64 `json:"totalMs"`
}

// Hop is one entry in a redirect chain.
type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	Location   string `json:"location"`
}

// Response is the immutable result of one HTTP transaction, shared by every
// check that needs it.
type Response struct {
	FinalURL      *neturl.URL
	StatusCode    int
	Status        string
	Proto         string
	Header        http.Header
	Body          []byte
	BodyTruncated bool
	ContentLength int64
	TLS           *tls.ConnectionState
	RemoteAddr    netip.Addr
	Hops          []Hop
	Timings       Timings
}

// Client performs safety-checked HTTP requests.
type Client struct {
	cfg      types.Config
	policy   dowurl.Policy
	resolver *net.Resolver
	http     *http.Client
	// dialed records every address actually connected to, so security checks
	// can report the true peers rather than a re-resolved answer.
	mu     sync.Mutex
	dialed []netip.Addr
	hopsMu sync.Mutex
	hops   []Hop
}

// ClientOptions configures a Client.
type ClientOptions struct {
	Config   types.Config
	Policy   dowurl.Policy
	Resolver *net.Resolver
}

// NewClient builds an HTTP client that validates every address at dial time
// and every redirect hop before it is followed.
func NewClient(opts ClientOptions) *Client {
	resolver := opts.Resolver
	if resolver == nil {
		resolver = &net.Resolver{}
	}
	c := &Client{cfg: opts.Config, policy: opts.Policy, resolver: resolver}

	transport := &http.Transport{
		DialContext:           c.safeDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   opts.Config.Timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS10, // observation tool: report weak TLS, do not refuse it
		},
	}
	c.http = &http.Client{
		Transport:     transport,
		Timeout:       opts.Config.Timeout,
		CheckRedirect: c.checkRedirect,
	}
	return c
}

// DialedAddrs returns the addresses this client connected to.
func (c *Client) DialedAddrs() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]netip.Addr, len(c.dialed))
	copy(out, c.dialed)
	return out
}

// safeDialContext resolves the host itself, validates every candidate address
// against the policy, and connects only to an approved address. Because
// validation happens here rather than before the request, a DNS answer that
// changes between validation and connection (DNS rebinding) cannot be used.
func (c *Client) safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed dial address %q", types.ErrInvalidURL, address)
	}

	addrs, err := c.resolveAddrs(ctx, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: c.cfg.Timeout, KeepAlive: 15 * time.Second}
	var lastErr error
	for _, addr := range addrs {
		if err := c.policy.CheckAddr(addr); err != nil {
			lastErr = err
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		c.mu.Lock()
		c.dialed = append(c.dialed, addr)
		c.mu.Unlock()
		return conn, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no usable address for %s", types.ErrUnreachable, host)
	}
	return nil, lastErr
}

func (c *Client) resolveAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		return []netip.Addr{addr}, nil
	}
	ips, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot resolve %s: %s", types.ErrUnreachable, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses for %s", types.ErrUnreachable, host)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		out = append(out, ip)
	}
	return out, nil
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 0 {
		prev := via[len(via)-1]
		if prev.Response != nil {
			c.hopsMu.Lock()
			c.hops = append(c.hops, Hop{
				URL:        prev.URL.String(),
				StatusCode: prev.Response.StatusCode,
				Location:   prev.Response.Header.Get("Location"),
			})
			c.hopsMu.Unlock()
		}
	}
	if len(via) > c.cfg.MaxRedirects {
		return fmt.Errorf("%w: stopped after %d hops", types.ErrTooManyRedirects, c.cfg.MaxRedirects)
	}
	target, err := dowurl.Normalize(req.URL.String())
	if err != nil {
		return fmt.Errorf("redirect target rejected: %w", err)
	}
	if err := c.policy.CheckRedirect(target); err != nil {
		return fmt.Errorf("redirect target rejected: %w", err)
	}
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	return nil
}

// Fetch performs a GET against target and returns the observed response. The
// redirect chain, phase timings and a size-capped body are captured. A
// response is returned even when the body could not be fully read.
func (c *Client) Fetch(ctx context.Context, target dowurl.Target) (*Response, error) {
	if err := c.policy.CheckTarget(target); err != nil {
		return nil, err
	}

	hops := make([]Hop, 0, c.cfg.MaxRedirects)
	var (
		start                       = time.Now()
		dnsStart, connStart, tlsAt  time.Time
		t                           Timings
		firstByte                   time.Time
		tlsState                    *tls.ConnectionState
	)
	t.DNSMS, t.ConnectMS, t.TLSMS = -1, -1, -1

	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				t.DNSMS = millis(time.Since(dnsStart))
			}
		},
		ConnectStart: func(string, string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connStart.IsZero() {
				t.ConnectMS = millis(time.Since(connStart))
			}
		},
		TLSHandshakeStart: func() { tlsAt = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && !tlsAt.IsZero() {
				t.TLSMS = millis(time.Since(tlsAt))
				s := state
				tlsState = &s
			}
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %s", types.ErrInternal, err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.http.Do(req) //nolint:bodyclose // closed below via defer on resp.Body
	if err != nil {
		return nil, classifyTransportError(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	c.hopsMu.Lock()
	hops = append(hops, c.hops...)
	c.hopsMu.Unlock()

	if !firstByte.IsZero() {
		t.TTFBMS = millis(firstByte.Sub(start))
	}
	body, truncated, readErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)
	if !firstByte.IsZero() {
		t.DownloadMS = millis(time.Since(firstByte))
	}
	t.TotalMS = millis(time.Since(start))

	if resp.TLS != nil {
		tlsState = resp.TLS
	}

	final := *resp.Request.URL
	out := &Response{
		FinalURL:      &final,
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Proto:         resp.Proto,
		Header:        resp.Header.Clone(),
		Body:          body,
		BodyTruncated: truncated,
		ContentLength: resp.ContentLength,
		TLS:           tlsState,
		Hops:          hops,
		Timings:       t,
	}
	if dialed := c.DialedAddrs(); len(dialed) > 0 {
		out.RemoteAddr = dialed[len(dialed)-1]
	}
	if readErr != nil && !errors.Is(readErr, types.ErrBodyTooLarge) {
		return out, fmt.Errorf("%w: reading body: %s", types.ErrUnreachable, readErr)
	}
	return out, nil
}

// redirectChain reconstructs the hop list from the response chain that
// net/http records in Response.Request and the previous responses.

func readCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return buf, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, types.ErrBodyTooLarge
	}
	return buf, false, nil
}

func classifyTransportError(err error) error {
	var unsafe error
	if errors.Is(err, types.ErrUnsafeTarget) || errors.Is(err, types.ErrTooManyRedirects) {
		return err
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %s", types.ErrTimeout, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s", types.ErrTimeout, err)
	}
	if strings.Contains(err.Error(), "stopped after") {
		return fmt.Errorf("%w: %s", types.ErrTooManyRedirects, err)
	}
	_ = unsafe
	return fmt.Errorf("%w: %s", types.ErrUnreachable, err)
}

func millis(d time.Duration) int64 { return d.Milliseconds() }
