package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// ResolverName identifies which resolver produced a DNSObservation.
type ResolverName string

// Resolver identifiers used in reports.
const (
	ResolverSystem     ResolverName = "system"
	ResolverCloudflare ResolverName = "cloudflare-doh"
	ResolverGoogle     ResolverName = "google-doh"
	ResolverQuad9      ResolverName = "quad9-doh"
)

// Default DoH endpoints, RFC 8484 wire format over HTTPS POST.
const (
	DefaultDoHCloudflare = "https://1.1.1.1/dns-query"
	DefaultDoHGoogle     = "https://8.8.8.8/dns-query"
	DefaultDoHQuad9      = "https://9.9.9.9/dns-query"
)

// RCode values reported for the system resolver, which does not expose the
// real wire-format response code through the standard library. These are
// inferred from net.DNSError and must not be treated as authoritative; DoH
// resolvers report the true RCODE decoded from the response message.
const (
	RCodeUnknown = "UNKNOWN"
)

// DNSObservation is one resolver's answer for one record type.
type DNSObservation struct {
	Resolver   ResolverName `json:"resolver"`
	RecordType string       `json:"recordType"`
	LatencyMS  int64        `json:"latencyMs"`
	Answers    []string     `json:"answers"`
	CNAME      []string     `json:"cname"`
	RCode      string       `json:"rcode"`
	Authoritative bool      `json:"rcodeAuthoritative"`
	DNSSECOK   bool         `json:"dnssecOk"`
	Err        string       `json:"error,omitempty"`
}

// DNSResult aggregates observations from every resolver for a host.
type DNSResult struct {
	Host         string           `json:"host"`
	Observations []DNSObservation `json:"observations"`
}

// Resolver is implemented by DNSClient and by test doubles. It lets checks
// depend on behaviour rather than a concrete network client.
type Resolver interface {
	Resolve(ctx context.Context, host string) DNSResult
}

// systemLookuper is the subset of *net.Resolver used by DNSClient. It is a
// separate interface so tests can inject a fake system resolver without
// touching the OS resolver.
type systemLookuper interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// DNSClient queries the system resolver and a configurable set of DoH
// resolvers. All dependencies are injected through DNSClientOptions so the
// client is fully testable without contacting real DNS infrastructure.
type DNSClient struct {
	httpClient     *http.Client
	systemResolver systemLookuper
	endpoints      map[ResolverName]string
}

// DNSClientOptions configures a DNSClient. Zero-value fields fall back to
// production defaults: the OS resolver and the public Cloudflare/Google/Quad9
// DoH endpoints.
type DNSClientOptions struct {
	Timeout        time.Duration
	HTTPClient     *http.Client
	SystemResolver systemLookuper
	Endpoints      map[ResolverName]string
}

// NewDNSClient builds a production DNS client bounded by timeout.
func NewDNSClient(timeout time.Duration) *DNSClient {
	return NewDNSClientWithOptions(DNSClientOptions{Timeout: timeout})
}

// NewDNSClientWithOptions builds a DNS client from explicit dependencies.
// Tests use this to inject httptest servers and fake resolvers.
func NewDNSClientWithOptions(opts DNSClientOptions) *DNSClient {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: opts.Timeout}
	}
	sysResolver := opts.SystemResolver
	if sysResolver == nil {
		sysResolver = net.DefaultResolver
	}
	endpoints := opts.Endpoints
	if endpoints == nil {
		endpoints = map[ResolverName]string{
			ResolverCloudflare: DefaultDoHCloudflare,
			ResolverGoogle:     DefaultDoHGoogle,
			ResolverQuad9:      DefaultDoHQuad9,
		}
	}
	return &DNSClient{httpClient: httpClient, systemResolver: sysResolver, endpoints: endpoints}
}

// Resolve queries A and AAAA records for host across the system resolver and
// every configured DoH resolver, concurrently, sharing ctx's deadline. It
// never returns an error: per-resolver failures are recorded on the
// observation so the caller always gets a complete, comparable result set.
func (c *DNSClient) Resolve(ctx context.Context, host string) DNSResult {
	type job struct {
		resolver ResolverName
		rtype    uint16
	}

	jobs := []job{
		{ResolverSystem, dns.TypeA},
		{ResolverSystem, dns.TypeAAAA},
	}
	for name := range c.endpoints {
		jobs = append(jobs, job{name, dns.TypeA}, job{name, dns.TypeAAAA})
	}

	results := make([]DNSObservation, len(jobs))
	done := make(chan int, len(jobs))
	for i, j := range jobs {
		go func(i int, j job) {
			results[i] = c.query(ctx, j.resolver, host, j.rtype)
			done <- i
		}(i, j)
	}
	for range jobs {
		<-done
	}
	return DNSResult{Host: host, Observations: results}
}

func (c *DNSClient) query(ctx context.Context, resolver ResolverName, host string, rtype uint16) DNSObservation {
	obs := DNSObservation{Resolver: resolver, RecordType: dns.TypeToString[rtype]}
	start := time.Now()

	if resolver == ResolverSystem {
		answers, rcode, err := c.querySystem(ctx, host, rtype)
		obs.LatencyMS = time.Since(start).Milliseconds()
		obs.Answers = answers
		obs.RCode = rcode
		obs.Authoritative = false
		if err != nil {
			obs.Err = err.Error()
		}
		return obs
	}

	answers, cname, rcode, dnssecOK, err := c.queryDoH(ctx, resolver, host, rtype)
	obs.LatencyMS = time.Since(start).Milliseconds()
	obs.Answers = answers
	obs.CNAME = cname
	obs.RCode = dns.RcodeToString[rcode]
	obs.Authoritative = err == nil
	obs.DNSSECOK = dnssecOK
	if err != nil {
		obs.Err = err.Error()
	}
	return obs
}

// querySystem resolves host using the injected system resolver. The standard
// library does not expose the wire-format RCODE for system lookups, so the
// returned code is a best-effort classification, not a decoded DNS response.
func (c *DNSClient) querySystem(ctx context.Context, host string, rtype uint16) ([]string, string, error) {
	network := "ip4"
	if rtype == dns.TypeAAAA {
		network = "ip6"
	}
	ips, err := c.systemResolver.LookupIP(ctx, network, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsNotFound:
				return nil, dns.RcodeToString[dns.RcodeNameError], err
			case dnsErr.IsTimeout:
				return nil, RCodeUnknown, err
			}
		}
		return nil, RCodeUnknown, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, dns.RcodeToString[dns.RcodeSuccess], nil
}

// queryDoH sends an RFC 8484 wire-format query over HTTPS POST and decodes
// the response, including the authoritative RCODE and the DNSSEC OK bit.
func (c *DNSClient) queryDoH(ctx context.Context, resolver ResolverName, host string, rtype uint16) (
	answers, cnames []string, rcode int, dnssecOK bool, err error,
) {
	endpoint, ok := c.endpoints[resolver]
	if !ok {
		return nil, nil, dns.RcodeServerFailure, false,
			fmt.Errorf("%w: no endpoint configured for resolver %q", types.ErrInternal, resolver)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), rtype)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	packed, perr := msg.Pack()
	if perr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("packing dns query: %w", perr)
	}

	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(packed)))
	if rerr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("building doh request: %w", rerr)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, derr := c.httpClient.Do(req)
	if derr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("doh request to %s: %w", resolver, derr)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, dns.RcodeServerFailure, false,
			fmt.Errorf("doh %s returned http status %d", resolver, resp.StatusCode)
	}

	body, ierr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if ierr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("reading doh response body: %w", ierr)
	}

	respMsg := new(dns.Msg)
	if uerr := respMsg.Unpack(body); uerr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("unpacking doh response: %w", uerr)
	}

	for _, rr := range respMsg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, v.A.String())
		case *dns.AAAA:
			answers = append(answers, v.AAAA.String())
		case *dns.CNAME:
			cnames = append(cnames, strings.TrimSuffix(v.Target, "."))
		}
	}
	if opt := respMsg.IsEdns0(); opt != nil {
		dnssecOK = opt.Do()
	}
	if respMsg.Rcode != dns.RcodeSuccess {
		return answers, cnames, respMsg.Rcode, dnssecOK,
			fmt.Errorf("doh %s returned rcode %s", resolver, dns.RcodeToString[respMsg.Rcode])
	}
	return answers, cnames, respMsg.Rcode, dnssecOK, nil
}
