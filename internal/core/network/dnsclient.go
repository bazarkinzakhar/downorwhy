package network

import (
	"bytes"
	"context"
	"sync"
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

// RCodeUnknown is reported for system-resolver answers whose true wire-format
// response code is not exposed by the standard library.
const RCodeUnknown = "UNKNOWN"

// dohResolverOrder fixes the order in which DoH resolvers are queried and
// reported. Iterating a Go map would produce a different observation order on
// every run, which would make reports non-deterministic.
var dohResolverOrder = []ResolverName{
	ResolverCloudflare,
	ResolverGoogle,
	ResolverQuad9,
}

// DNSObservation is one resolver's answer for one record type.
type DNSObservation struct {
	Resolver   ResolverName `json:"resolver"`
	RecordType string       `json:"recordType"`
	LatencyMS  int64        `json:"latencyMs"`
	Answers    []string     `json:"answers"`
	CNAME      []string     `json:"cname"`
	RCode      string       `json:"rcode"`
	// Authoritative reports whether RCode was decoded from a real DNS
	// response. It is false for system-resolver answers, where the standard
	// library hides the wire-format response code.
	Authoritative bool `json:"rcodeAuthoritative"`
	// DNSSECValidated reflects the AD (authenticated data) bit, meaning the
	// resolver cryptographically validated the answer. It is false both for
	// unsigned zones and for resolvers that do not validate, so it must never
	// be treated on its own as evidence of a DNSSEC failure.
	DNSSECValidated bool   `json:"dnssecValidated"`
	Err             string `json:"error,omitempty"`
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

// systemLookuper is the subset of *net.Resolver used by DNSClient, kept
// separate so tests can inject a fake system resolver.
type systemLookuper interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// DNSClient queries the system resolver and a configurable set of DoH
// resolvers. All dependencies are injected so the client is fully testable
// without contacting real DNS infrastructure.
type DNSClient struct {
	httpClient     *http.Client
	systemResolver systemLookuper
	endpoints      map[ResolverName]string
}

// DNSClientOptions configures a DNSClient. Zero-value fields fall back to
// production defaults: the OS resolver and the public DoH endpoints.
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
func NewDNSClientWithOptions(opts DNSClientOptions) *DNSClient {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: opts.Timeout}
	}

	systemResolver := opts.SystemResolver
	if systemResolver == nil {
		systemResolver = net.DefaultResolver
	}

	endpoints := opts.Endpoints
	if endpoints == nil {
		endpoints = map[ResolverName]string{
			ResolverCloudflare: DefaultDoHCloudflare,
			ResolverGoogle:     DefaultDoHGoogle,
			ResolverQuad9:      DefaultDoHQuad9,
		}
	}

	return &DNSClient{
		httpClient:     httpClient,
		systemResolver: systemResolver,
		endpoints:      endpoints,
	}
}

// Resolve queries A and AAAA records for host across the system resolver and
// every configured DoH resolver, concurrently, sharing ctx's deadline.
// Observations are returned in a fixed order regardless of completion order.
// Resolve never returns an error: per-resolver failures are recorded on the
// observation so the caller always receives a comparable result set.
func (c *DNSClient) Resolve(ctx context.Context, host string) DNSResult {
	type job struct {
		resolver ResolverName
		rtype    uint16
	}

	jobs := []job{
		{ResolverSystem, dns.TypeA},
		{ResolverSystem, dns.TypeAAAA},
	}
	for _, name := range dohResolverOrder {
		if _, ok := c.endpoints[name]; !ok {
			continue
		}
		jobs = append(jobs, job{name, dns.TypeA}, job{name, dns.TypeAAAA})
	}

	results := make([]DNSObservation, len(jobs))

	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(index int, spec job) {
			defer wg.Done()
			results[index] = c.query(ctx, spec.resolver, host, spec.rtype)
		}(i, j)
	}
	wg.Wait()

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

	answers, cnames, rcode, validated, err := c.queryDoH(ctx, resolver, host, rtype)
	obs.LatencyMS = time.Since(start).Milliseconds()
	obs.Answers = answers
	obs.CNAME = cnames
	obs.RCode = dns.RcodeToString[rcode]
	obs.Authoritative = err == nil
	obs.DNSSECValidated = validated
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
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, dns.RcodeToString[dns.RcodeNameError], err
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
// the response, including the authoritative RCODE and the AD bit.
func (c *DNSClient) queryDoH(ctx context.Context, resolver ResolverName, host string, rtype uint16) (
	answers, cnames []string, rcode int, dnssecValidated bool, err error,
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

	packed, packErr := msg.Pack()
	if packErr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("packing dns query: %w", packErr)
	}

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if reqErr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("building doh request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("doh request to %s: %w", resolver, doErr)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, dns.RcodeServerFailure, false,
			fmt.Errorf("doh %s returned http status %d", resolver, resp.StatusCode)
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("reading doh response body: %w", readErr)
	}

	respMsg := new(dns.Msg)
	if unpackErr := respMsg.Unpack(body); unpackErr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("unpacking doh response: %w", unpackErr)
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

	dnssecValidated = respMsg.AuthenticatedData

	if respMsg.Rcode != dns.RcodeSuccess {
		return answers, cnames, respMsg.Rcode, dnssecValidated,
			fmt.Errorf("doh %s returned rcode %s", resolver, dns.RcodeToString[respMsg.Rcode])
	}

	return answers, cnames, respMsg.Rcode, dnssecValidated, nil
}
