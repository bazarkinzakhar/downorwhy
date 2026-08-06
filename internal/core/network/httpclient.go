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
	"time"

	"github.com/downorwhy/downorwhy/internal/core/types"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
)

type Timings struct {
	DNSMS      int64 `json:"dnsMs"`
	ConnectMS  int64 `json:"connectMs"`
	TLSMS      int64 `json:"tlsMs"`
	TTFBMS     int64 `json:"ttfbMs"`
	DownloadMS int64 `json:"downloadMs"`
	TotalMS    int64 `json:"totalMs"`
}

type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	Location   string `json:"location"`
}

type Response struct {
	FinalURL        *neturl.URL
	StatusCode      int
	Status          string
	Proto           string
	Header          http.Header
	Body            []byte
	BodyTruncated   bool
	ContentLength   int64
	Compressed      bool
	ContentEncoding string
	TLS             *tls.ConnectionState
	RemoteAddr      netip.Addr
	Hops            []Hop
	Timings         Timings
}

type Client struct {
	cfg    types.Config
	policy dowurl.Policy
	dialer *SafeDialer
	http   *http.Client
}

type ClientOptions struct {
	Config   types.Config
	Policy   dowurl.Policy
	Resolver IPLookuper
}

func NewClient(opts ClientOptions) *Client {
	dialer := NewSafeDialer(opts.Policy, opts.Resolver, opts.Config.Timeout)

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

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.Config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{cfg: opts.Config, policy: opts.Policy, dialer: dialer, http: httpClient}
}

func (c *Client) DialedAddrs() []netip.Addr { return c.dialer.DialedAddrs() }

func (c *Client) Fetch(ctx context.Context, target dowurl.Target) (*Response, error) {
	if err := c.policy.CheckTarget(target); err != nil {
		return nil, err
	}

	var (
		hops          []Hop
		currentTarget = target
		start         = time.Now()
	)

	for hopCount := 0; ; hopCount++ {
		resp, timings, tlsSnap, reqErr := c.singleHop(ctx, currentTarget, &start)
		if reqErr != nil {
			return nil, reqErr
		}

		if !isRedirect(resp.StatusCode) || hopCount >= c.cfg.MaxRedirects {
			body, truncated, bodyErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)
			resp.Body.Close()

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
				TLS:             tlsSnap,
				Hops:            hops,
				Timings:         timings,
			}

			if dialed := c.DialedAddrs(); len(dialed) > 0 {
				out.RemoteAddr = dialed[len(dialed)-1]
			}

			if hopCount >= c.cfg.MaxRedirects && isRedirect(resp.StatusCode) {
				return out, fmt.Errorf("%w: stopped after %d hops", types.ErrTooManyRedirects, c.cfg.MaxRedirects)
			}

			if bodyErr != nil && !errors.Is(bodyErr, types.ErrBodyTooLarge) {
				return out, fmt.Errorf("%w: reading body: %s", types.ErrUnreachable, bodyErr)
			}

			return out, nil
		}

		resp.Body.Close()

		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, fmt.Errorf("%w: redirect with empty Location", types.ErrUnreachable)
		}

		nextURL, err := resp.Request.URL.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed redirect Location", types.ErrUnreachable)
		}

		nextTarget, err := dowurl.Normalize(nextURL.String())
		if err != nil {
			return nil, fmt.Errorf("redirect target rejected: %w", err)
		}

		if err := c.policy.CheckRedirect(nextTarget); err != nil {
			return nil, fmt.Errorf("redirect target rejected: %w", err)
		}

		hops = append(hops, Hop{
			URL:        currentTarget.String(),
			StatusCode: resp.StatusCode,
			Location:   loc,
		})

		currentTarget = nextTarget
	}
}

func (c *Client) singleHop(ctx context.Context, target dowurl.Target, start *time.Time) (
	*http.Response, Timings, *tls.ConnectionState, error,
) {
	var (
		tlsStart time.Time
		tlsState *tls.ConnectionState
		ttfbAt   time.Time
		timings  = Timings{DNSMS: -1, ConnectMS: -1, TLSMS: -1, TTFBMS: -1, DownloadMS: -1}
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
		GotFirstResponseByte: func() { ttfbAt = time.Now() },
	}

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		http.MethodGet,
		target.String(),
		http.NoBody,
	)
	if err != nil {
		return nil, timings, nil, fmt.Errorf("%w: building request: %s", types.ErrInternal, err)
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, timings, nil, classifyTransportError(err)
	}

	if !ttfbAt.IsZero() {
		timings.TTFBMS = ttfbAt.Sub(*start).Milliseconds()
	}
	timings.TotalMS = time.Since(*start).Milliseconds()

	dialStats := c.dialer.Stats()
	timings.DNSMS = dialStats.DNSMS
	timings.ConnectMS = dialStats.ConnectMS

	return resp, timings, tlsState, nil
}

func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
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