package network_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/network"
)

func newDoHFixture(t *testing.T, a, aaaa, cname []string, rcode int, dnssecOK bool) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		require.NoError(t, readErr)

		q := new(dns.Msg)
		require.NoError(t, q.Unpack(body))

		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = rcode
		resp.AuthenticatedData = dnssecOK

		qname := q.Question[0].Name
		switch q.Question[0].Qtype {
		case dns.TypeA:
			for _, ip := range a {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr:     dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:       net.ParseIP(ip),
				})
			}
		case dns.TypeAAAA:
			for _, ip := range aaaa {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP(ip),
				})
			}
		}
		for _, target := range cname {
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: dns.Fqdn(target),
			})
		}

		packed, packErr := resp.Pack()
		require.NoError(t, packErr)

		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	t.Cleanup(srv.Close)

	return srv
}

type fakeSystemResolver struct {
	ips []net.IP
	err error
}

func (f fakeSystemResolver) LookupIP(_ context.Context, _, _ string) ([]net.IP, error) {
	return f.ips, f.err
}

func TestDNSClientResolveSuccess(t *testing.T) {
	srv := newDoHFixture(t,
		[]string{"93.184.216.34"},
		[]string{"2606:2800:220:1:248:1893:25c8:1946"},
		nil,
		dns.RcodeSuccess,
		true,
	)

	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout: 2 * time.Second,
		SystemResolver: fakeSystemResolver{
			ips: []net.IP{net.ParseIP("93.184.216.34")},
		},
		Endpoints: map[network.ResolverName]string{
			network.ResolverCloudflare: srv.URL,
		},
	})

	result := client.Resolve(context.Background(), "example.com")
	require.Equal(t, "example.com", result.Host)
	require.Len(t, result.Observations, 4)

	var sawCloudflareA, sawSystemA bool
	for _, obs := range result.Observations {
		switch {
		case obs.Resolver == network.ResolverCloudflare && obs.RecordType == "A":
			sawCloudflareA = true
			require.Equal(t, []string{"93.184.216.34"}, obs.Answers)
			require.Equal(t, "NOERROR", obs.RCode)
			require.True(t, obs.DNSSECValidated)
			require.True(t, obs.Authoritative)
		case obs.Resolver == network.ResolverSystem && obs.RecordType == "A":
			sawSystemA = true
			require.Equal(t, []string{"93.184.216.34"}, obs.Answers)
			require.False(t, obs.Authoritative)
		}
	}
	require.True(t, sawCloudflareA)
	require.True(t, sawSystemA)
}

func TestDNSClientResolveNXDOMAIN(t *testing.T) {
	srv := newDoHFixture(t, nil, nil, nil, dns.RcodeNameError, false)

	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout: 2 * time.Second,
		SystemResolver: fakeSystemResolver{
			err: &net.DNSError{IsNotFound: true, Err: "no such host"},
		},
		Endpoints: map[network.ResolverName]string{
			network.ResolverGoogle: srv.URL,
		},
	})

	result := client.Resolve(context.Background(), "not-a-real-domain.invalid")
	for _, obs := range result.Observations {
		require.Empty(t, obs.Answers)
		if obs.Resolver == network.ResolverGoogle && obs.RecordType == "A" {
			require.Equal(t, "NXDOMAIN", obs.RCode)
			require.NotEmpty(t, obs.Err)
		}
		if obs.Resolver == network.ResolverSystem && obs.RecordType == "A" {
			require.Equal(t, "NXDOMAIN", obs.RCode)
		}
	}
}

func TestDNSClientCNAMEChain(t *testing.T) {
	srv := newDoHFixture(t, []string{"1.2.3.4"}, nil, []string{"cdn.example.net"}, dns.RcodeSuccess, false)

	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout: 2 * time.Second,
		SystemResolver: fakeSystemResolver{
			ips: []net.IP{net.ParseIP("1.2.3.4")},
		},
		Endpoints: map[network.ResolverName]string{
			network.ResolverQuad9: srv.URL,
		},
	})

	result := client.Resolve(context.Background(), "www.example.com")
	found := false
	for _, obs := range result.Observations {
		if obs.Resolver == network.ResolverQuad9 && obs.RecordType == "A" {
			found = true
			require.Equal(t, []string{"cdn.example.net"}, obs.CNAME)
		}
	}
	require.True(t, found)
}

func TestDNSClientDoHServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout: 2 * time.Second,
		SystemResolver: fakeSystemResolver{
			ips: []net.IP{net.ParseIP("1.1.1.1")},
		},
		Endpoints: map[network.ResolverName]string{
			network.ResolverCloudflare: srv.URL,
		},
	})

	result := client.Resolve(context.Background(), "example.com")
	for _, obs := range result.Observations {
		if obs.Resolver == network.ResolverCloudflare {
			require.NotEmpty(t, obs.Err)
			require.False(t, obs.Authoritative)
		}
	}
}

func TestDNSClientContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout: 2 * time.Second,
		SystemResolver: fakeSystemResolver{
			ips: []net.IP{net.ParseIP("1.1.1.1")},
		},
		Endpoints: map[network.ResolverName]string{
			network.ResolverGoogle: srv.URL,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result := client.Resolve(ctx, "example.com")
	var sawTimeout bool
	for _, obs := range result.Observations {
		if obs.Resolver == network.ResolverGoogle && obs.Err != "" {
			sawTimeout = true
		}
	}
	require.True(t, sawTimeout)
}

func TestDNSClientNoDoHEndpointsConfigured(t *testing.T) {
	client := network.NewDNSClientWithOptions(network.DNSClientOptions{
		Timeout:        time.Second,
		SystemResolver: fakeSystemResolver{ips: []net.IP{net.ParseIP("1.1.1.1")}},
		Endpoints:      map[network.ResolverName]string{},
	})

	result := client.Resolve(context.Background(), "example.com")
	require.Len(t, result.Observations, 2)
	require.Equal(t, network.ResolverSystem, result.Observations[0].Resolver)
}
