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

// DoH endpoints. All three are queried over HTTPS using the RFC 8484 wire
// format (application/dns-message), which does not require a JSON parser.
const (
	dohCloudflare = "https://1.1.1.1/dns-query"
	dohGoogle     = "https://8.8.8.8/dns-query"
	dohQuad9      = "https://9.9.9.9/dns-query"
)

// DNSObservation is one resolver's answer for one record type.
type DNSObservation struct {
	Resolver   ResolverName `json:"resolver"`
	RecordType string       `json:"recordType"`
	LatencyMS  int64        `json:"latencyMs"`
	Answers    []string     `json:"answers"`
	CNAME      []string     `json:"cname"`
	RCode      string       `json:"rcode"`
	DNSSECOK   bool         `json:"dnssecOk"`
	Err        string       `json:"error,omitempty"`
}

// DNSResult aggregates observations from every resolver for a host.
type DNSResult struct {
	Host         string           `json:"host"`
	Observations []DNSObservation `json:"observations"`
}

// DNSClient queries the system resolver and a fixed set of DoH resolvers.
type DNSClient struct {
	httpClient *http.Client
	systemAddr func(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

// NewDNSClient builds a DNS client. timeout bounds every individual query.
func NewDNSClient(timeout time.Duration) *DNSClient {
	return &DNSClient{
		httpClient: &http.Client{Timeout: timeout},
		systemAddr: net.DefaultResolver.LookupIPAddr,
	}
}

// Resolve queries A and AAAA records for host across the system resolver and
// all three DoH resolvers, concurrently, sharing ctx's deadline. It never
// returns an error: per-resolver failures are recorded on the observation.
func (c *DNSClient) Resolve(ctx context.Context, host string) DNSResult {
	type job struct {
		resolver ResolverName
		rtype    uint16
	}
	jobs := []job{
		{ResolverSystem, dns.TypeA},
		{ResolverSystem, dns.TypeAAAA},
		{ResolverCloudflare, dns.TypeA},
		{ResolverCloudflare, dns.TypeAAAA},
		{ResolverGoogle, dns.TypeA},
		{ResolverGoogle, dns.TypeAAAA},
		{ResolverQuad9, dns.TypeA},
		{ResolverQuad9, dns.TypeAAAA},
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

	var (
		answers []string
		cname   []string
		rcode   int
		dnssec  bool
		err     error
	)
	if resolver == ResolverSystem {
		answers, err = c.querySystem(ctx, host, rtype)
		rcode = dns.RcodeSuccess
		if err != nil && isNXDomain(err) {
			rcode = dns.RcodeNameError
		}
	} else {
		answers, cname, rcode, dnssec, err = c.queryDoH(ctx, resolver, host, rtype)
	}

	obs.LatencyMS = time.Since(start).Milliseconds()
	obs.Answers = answers
	obs.CNAME = cname
	obs.RCode = dns.RcodeToString[rcode]
	obs.DNSSECOK = dnssec
	if err != nil {
		obs.Err = err.Error()
	}
	return obs
}

func (c *DNSClient) querySystem(ctx context.Context, host string, rtype uint16) ([]string, error) {
	network := "ip4"
	if rtype == dns.TypeAAAA {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

func isNXDomain(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// queryDoH sends an RFC 8484 wire-format query over HTTPS POST.
func (c *DNSClient) queryDoH(ctx context.Context, resolver ResolverName, host string, rtype uint16) (
	answers, cnames []string, rcode int, dnssecOK bool, err error,
) {
	endpoint, uerr := dohEndpoint(resolver)
	if uerr != nil {
		return nil, nil, dns.RcodeServerFailure, false, uerr
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), rtype)
	msg.SetEdns0(4096, true) // request DNSSEC OK
	msg.RecursionDesired = true

	packed, perr := msg.Pack()
	if perr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("packing dns query: %w", perr)
	}

	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(packed)))
	if rerr != nil {
		return nil, nil, dns.RcodeServerFailure, false, rerr
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, derr := c.httpClient.Do(req)
	if derr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("doh request: %w", derr)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, dns.RcodeServerFailure, false,
			fmt.Errorf("doh %s returned status %d", resolver, resp.StatusCode)
	}

	body, ierr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if ierr != nil {
		return nil, nil, dns.RcodeServerFailure, false, fmt.Errorf("reading doh response: %w", ierr)
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
	return answers, cnames, respMsg.Rcode, dnssecOK, nil
}

func dohEndpoint(resolver ResolverName) (string, error) {
	switch resolver {
	case ResolverCloudflare:
		return dohCloudflare, nil
	case ResolverGoogle:
		return dohGoogle, nil
	case ResolverQuad9:
		return dohQuad9, nil
	default:
		return "", fmt.Errorf("%w: no DoH endpoint for resolver %q", types.ErrInternal, resolver)
	}
}

// safeguard: ensure the safeurl package stays linked for callers that need it
// alongside DNS resolution (checks import both). Referencing the package here
// keeps import errors visible at the DNS layer rather than deep in a check.
