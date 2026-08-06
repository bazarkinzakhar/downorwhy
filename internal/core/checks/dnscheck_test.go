package checks_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/checks"
	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// fakeResolver is a deterministic stand-in for network.DNSClient.
type fakeResolver struct {
	result network.DNSResult
}

func (f fakeResolver) Resolve(_ context.Context, host string) network.DNSResult {
	r := f.result
	r.Host = host
	return r
}

func obs(resolver network.ResolverName, rtype string, answers []string, latencyMS int64, authoritative, dnssecOK bool, errMsg string) network.DNSObservation {
	return network.DNSObservation{
		Resolver:      resolver,
		RecordType:    rtype,
		Answers:       answers,
		LatencyMS:     latencyMS,
		Authoritative: authoritative,
		DNSSECValidated: dnssecOK,
		Err:           errMsg,
		RCode:         "NOERROR",
	}
}

func TestRunDNSHealthy(t *testing.T) {
	resolver := fakeResolver{result: network.DNSResult{
		Observations: []network.DNSObservation{
			obs(network.ResolverSystem, "A", []string{"93.184.216.34"}, 20, false, false, ""),
			obs(network.ResolverSystem, "AAAA", []string{"2606:2800:220:1:248:1893:25c8:1946"}, 20, false, false, ""),
			obs(network.ResolverCloudflare, "A", []string{"93.184.216.34"}, 30, true, true, ""),
			obs(network.ResolverCloudflare, "AAAA", []string{"2606:2800:220:1:248:1893:25c8:1946"}, 30, true, true, ""),
			obs(network.ResolverGoogle, "A", []string{"93.184.216.34"}, 25, true, true, ""),
			obs(network.ResolverGoogle, "AAAA", []string{"2606:2800:220:1:248:1893:25c8:1946"}, 25, true, true, ""),
			obs(network.ResolverQuad9, "A", []string{"93.184.216.34"}, 28, true, true, ""),
			obs(network.ResolverQuad9, "AAAA", []string{"2606:2800:220:1:248:1893:25c8:1946"}, 28, true, true, ""),
		},
	}}

	result := checks.RunDNS(context.Background(), "example.com", resolver)
	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
	require.Contains(t, result.Summary, "example.com")
}

func TestRunDNSNoAnswerIsCritical(t *testing.T) {
	resolver := fakeResolver{result: network.DNSResult{
		Observations: []network.DNSObservation{
			obs(network.ResolverSystem, "A", nil, 20, false, false, "no such host"),
			obs(network.ResolverSystem, "AAAA", nil, 20, false, false, "no such host"),
			obs(network.ResolverCloudflare, "A", nil, 30, true, false, "doh returned rcode NXDOMAIN"),
			obs(network.ResolverCloudflare, "AAAA", nil, 30, true, false, "doh returned rcode NXDOMAIN"),
		},
	}}

	result := checks.RunDNS(context.Background(), "definitely-not-real.invalid", resolver)
	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, types.SeverityCritical, result.Findings[0].Severity)
	require.Equal(t, types.OwnerDNSProvider, result.Findings[0].Owner)
	require.Equal(t, types.LayerDNS, result.Findings[0].Layer)
}

func TestRunDNSResolverFailureIsWarning(t *testing.T) {
	resolver := fakeResolver{result: network.DNSResult{
		Observations: []network.DNSObservation{
			obs(network.ResolverSystem, "A", []string{"1.2.3.4"}, 20, false, false, ""),
			obs(network.ResolverCloudflare, "A", []string{"1.2.3.4"}, 30, true, true, ""),
			obs(network.ResolverGoogle, "A", nil, 5000, true, false, "doh request to google-doh: context deadline exceeded"),
		},
	}}

	result := checks.RunDNS(context.Background(), "example.com", resolver)
	require.Equal(t, types.CheckStatusWarn, result.Status)

	var sawFailureFinding bool
	for _, f := range result.Findings {
		if f.Title == "One or more DNS resolvers failed" {
			sawFailureFinding = true
			require.Equal(t, types.SeverityWarning, f.Severity)
		}
	}
	require.True(t, sawFailureFinding)
}

func TestRunDNSSlowResolutionIsWarning(t *testing.T) {
	resolver := fakeResolver{result: network.DNSResult{
		Observations: []network.DNSObservation{
			obs(network.ResolverSystem, "A", []string{"1.2.3.4"}, 900, false, false, ""),
			obs(network.ResolverCloudflare, "A", []string{"1.2.3.4"}, 30, true, true, ""),
		},
	}}

	result := checks.RunDNS(context.Background(), "slow.example.com", resolver)
	var sawSlow bool
	for _, f := range result.Findings {
		if f.Title == "Slow DNS resolution" {
			sawSlow = true
		}
	}
	require.True(t, sawSlow)
}

func TestRunDNSDisagreementIsWarning(t *testing.T) {
	resolver := fakeResolver{result: network.DNSResult{
		Observations: []network.DNSObservation{
			obs(network.ResolverSystem, "A", []string{"1.1.1.1"}, 20, false, false, ""),
			obs(network.ResolverCloudflare, "A", []string{"1.1.1.1"}, 30, true, true, ""),
			obs(network.ResolverGoogle, "A", []string{"2.2.2.2"}, 30, true, true, ""),
		},
	}}

	result := checks.RunDNS(context.Background(), "split.example.com", resolver)
	var sawDisagreement bool
	for _, f := range result.Findings {
		if f.Title == "Resolvers disagree on A records" {
			sawDisagreement = true
			require.Equal(t, types.SeverityWarning, f.Severity)
		}
	}
	require.True(t, sawDisagreement)
}