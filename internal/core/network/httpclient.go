package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/types"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
)

// Timings holds the phase breakdown of a single HTTP transaction. Values are
// milliseconds; -1 means the phase did not occur or could not be measured.
type Timings struct {
	DNSMS      int64 `json:"dnsMs"`
	ConnectMS  int64 `json:"connectMs"`
	TLSMS      int64 `json:"tlsMs"`
	TTFBMS     int64 `json:"ttfbMs"`
	DownloadMS int64 `json:"downloadMs"`
	TotalMS    int64 `json:"totalMs"`
}

// Hop is one redirect in a chain, recorded before the hop is followed.
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
	// Compressed reports whether the response travelled over the wire in a
	// compressed encoding. When the transport decoded gzip transparently the
	// Content-Encoding header is removed from Header, so this flag is the
	// authoritative signal.
	Compressed bool
	// ContentEncoding is the wire encoding actually used, or an empty string
	// when the response was sent uncompressed.
	ContentEncoding string
	TLS             *tls.ConnectionState
	RemoteAddr      netip.Addr
	Hops            []Hop
	Timings         Timings
}

// Client performs a single, safety-checked HTTP GET per scan target. It
// accumulates redirect hops and dialed addresses for the lifetime of one
// Fetch call and is not designed to be reused across unrelated requests.
type Client struct {
	cfg    types.Config
	policy dowurl.Policy
	dialer *SafeDialer
	http   *http.Client

	hopsMu sync.Mutex
	hops   []Hop
}

// ClientOptions configures a Client. Resolver is injected so tests can supply
// a stub; nil uses net.DefaultResolver.
type ClientOptions struct {
	Config   types.Config
	Policy   dowurl.Policy
	Resolver IPLookuper
}

// NewClient builds an HTTP client whose transport dials exclusively through a
// SafeDialer, so every connection it makes is subject to the SSRF policy,
// including connections opened to follow a redirect.
func NewClient(opts ClientOptions) *Client {
	dialer := NewSafeDialer(opts.Policy, opts.Resolver, opts.Config.Timeout)
	c := &Client{cfg: opts.Config, policy: opts.Policy, dialer: dialer}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   opts.Config.Timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS10,
		},
	}

	c.http = &http.Client{
		Transport:     transport,
		Timeout:       opts.Config.Timeout,
		CheckRedirect: c.checkRedirect,
	}

	return c
}

// DialedAddrs returns every address this client has connected to.
func (c *Client) DialedAddrs() []netip.Addr { return c.dialer.DialedAddrs() }

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	// The response that triggered THIS redirect is the last response in via.
	// For the first redirect, via has 1 element and its Response is the
	// initial 3xx response. For subsequent redirects, each via element's
	// Response is the previous 3xx.
	lastIdx := len(via) - 1
	if lastIdx >= 0 {
		lastReq := via[lastIdx]
		if lastReq.Response != nil {
			c.hopsMu.Lock()
			c.hops = append(c.hops, Hop{
				URL:        lastReq.URL.String(),
				StatusCode: lastReq.Response.StatusCode,
				Location:   lastReq.Response.Header.Get("Location"),
			})
			c.hopsMu.Unlock()
		}
	}

	if len(via) >= c.cfg.MaxRedirects {
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
// response is returned even when the body could not be fully read, so a
// broken target still yields a diagnosable result.
func (c *Client) Fetch(ctx context.Context, target dowurl.Target) (*Response, error) {
	if err := c.policy.CheckTarget(target); err != nil {
		return nil, err
	}

	c.hopsMu.Lock()
	c.hops = nil
	c.hopsMu.Unlock()

	var (
		start     = time.Now()
		tlsStart  time.Time
		firstByte time.Time
		tlsState  *tls.ConnectionState
		timings   = Timings{DNSMS: -1, ConnectMS: -1, TLSMS: -1, TTFBMS: -1, DownloadMS: -1}
	)

	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && !tlsStart.IsZero() {
				timings.TLSMS = time.Since(tlsStart).Milliseconds()
				snapshot := state
				tlsState = &snapshot
			}
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		http.MethodGet,
		target.String(),
		http.NoBody,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %s", types.ErrInternal, err)
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, classifyTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !firstByte.IsZero() {
		timings.TTFBMS = firstByte.Sub(start).Milliseconds()
	}

	body, truncated, readErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)

	if !firstByte.IsZero() {
		timings.DownloadMS = time.Since(firstByte).Milliseconds()
	}
	timings.TotalMS = time.Since(start).Milliseconds()

	dialStats := c.dialer.Stats()
	timings.DNSMS = dialStats.DNSMS
	timings.ConnectMS = dialStats.ConnectMS

	if resp.TLS != nil {
		tlsState = resp.TLS
	}

	c.hopsMu.Lock()
	hops := append([]Hop(nil), c.hops...)
	c.hopsMu.Unlock()

	contentEncoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	compressed := contentEncoding != ""
	if resp.Uncompressed {
		compressed = true
		contentEncoding = "gzip"
	}

	finalURL := *resp.Request.URL

	out := &Response{
		FinalURL:        &finalURL,
		StatusCode:      resp.StatusCode,
		Status:          resp.Status,
		Proto:           resp.Proto,
		Header:          resp.Header.Clone(),
		Body:            body,
		BodyTruncated:   truncated,
		ContentLength:   resp.ContentLength,
		Compressed:      compressed,
		ContentEncoding: contentEncoding,
		TLS:             tlsState,
		Hops:            hops,
		Timings:         timings,
	}

	if dialed := c.DialedAddrs(); len(dialed) > 0 {
		out.RemoteAddr = dialed[len(dialed)-1]
	}

	if readErr != nil && !errors.Is(readErr, types.ErrBodyTooLarge) {
		return out, fmt.Errorf("%w: reading body: %s", types.ErrUnreachable, readErr)
	}

	return out, nil
}

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
	if errors.Is(err, types.ErrUnsafeTarget) || errors.Is(err, types.ErrTooManyRedirects) {
		return err
	}

	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		if errors.Is(urlErr.Err, types.ErrUnsafeTarget) || errors.Is(urlErr.Err, types.ErrTooManyRedirects) {
			return urlErr.Err
		}
		if urlErr.Timeout() {
			return fmt.Errorf("%w: %s", types.ErrTimeout, err)
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s", types.ErrTimeout, err)
	}

	return fmt.Errorf("%w: %s", types.ErrUnreachable, err)
}
