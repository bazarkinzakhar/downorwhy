// Package checks contains one file per DownOrWhy check. Every check exposes a
// Run-style function with a signature tailored to the data it needs; the
// scanner package wires these together. See docs/architecture.md.
package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// DNSSlowThreshold flags a resolver as slow above this latency.
const DNSSlowThreshold = 500 * time.Millisecond

// resolverRecordKey groups observations by resolver and record type so
// answer sets can be compared for cross-resolver disagreement.
type resolverRecordKey struct {
	Resolver   string
	RecordType string
}

// RunDNS resolves host through resolver and evaluates the answers for
// outages, resolver disagreement, latency and DNSSEC posture. resolver is an
// interface so production code injects network.DNSClient and tests inject a
// deterministic fake.
func RunDNS(ctx context.Context, host string, resolver network.Resolver) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckDNS)
	result.Status = types.CheckStatusPass

	dnsResult := resolver.Resolve(ctx, host)

	answersByKey := map[resolverRecordKey][]string{}
	anyAnswer := false
	var slowResolvers []string
	var failedResolvers []string
	var dnssecFailures []string

	for _, obs := range dnsResult.Observations {
		key := resolverRecordKey{Resolver: string(obs.Resolver), RecordType: obs.RecordType}
		if len(obs.Answers) > 0 {
			anyAnswer = true
			answersByKey[key] = append(answersByKey[key], obs.Answers...)
		}
		if obs.Err != "" {
			failedResolvers = append(failedResolvers, fmt.Sprintf("%s/%s: %s", obs.Resolver, obs.RecordType, obs.Err))
		}
		if time.Duration(obs.LatencyMS)*time.Millisecond > DNSSlowThreshold {
			slowResolvers = append(slowResolvers, fmt.Sprintf("%s/%s (%dms)", obs.Resolver, obs.RecordType, obs.LatencyMS))
		}
		if obs.Authoritative && !obs.DNSSECOK && len(obs.Answers) > 0 {
			dnssecFailures = append(dnssecFailures, fmt.Sprintf("%s/%s", obs.Resolver, obs.RecordType))
		}
	}

	result.Set("host", host)
	result.Set("observations", dnsResult.Observations)

	if !anyAnswer {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerDNS,
			Title:    "Domain does not resolve",
			Description: "No resolver returned an A or AAAA record for this host. The domain " +
				"either has no DNS records, does not exist, or every queried resolver failed independently.",
			Evidence: map[string]interface{}{"observations": dnsResult.Observations},
			Owner:    types.OwnerDNSProvider,
		})
		result.Status = types.CheckStatusFail
		result.Summary = "no resolver returned an address for " + host
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	if len(failedResolvers) > 0 {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerDNS,
			Title:    "One or more DNS resolvers failed",
			Description: "At least one resolver returned an error while others succeeded. This can " +
				"indicate resolver-specific blocking, propagation lag, or an intermittent authoritative " +
				"nameserver issue.",
			Evidence: map[string]interface{}{"failedQueries": failedResolvers},
			Owner:    types.OwnerDNSProvider,
		})
	}

	if len(slowResolvers) > 0 {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerDNS,
			Title:    "Slow DNS resolution",
			Description: fmt.Sprintf("DNS lookups took longer than %s. Slow DNS delays every "+
				"subsequent connection to this site, including the first byte of every page load.", DNSSlowThreshold),
			Evidence: map[string]interface{}{"slowQueries": slowResolvers},
			Owner:    types.OwnerDNSProvider,
		})
	}

	if f := detectDisagreement(answersByKey); f != nil {
		result.AddFinding(*f)
	}

	if len(dnssecFailures) > 0 {
		result.AddFinding(types.Finding{
			Severity: types.SeverityInfo,
			Layer:    types.LayerDNS,
			Title:    "DNSSEC validation not confirmed",
			Description: "One or more resolvers returned an answer without the DNSSEC OK bit set on " +
				"the response, meaning validation could not be confirmed for this query. This is expected " +
				"for zones that do not sign their records and is informational only.",
			Evidence: map[string]interface{}{"queries": dnssecFailures},
			Owner:    types.OwnerDNSProvider,
		})
	}

	result.Summary = fmt.Sprintf("resolved %s via %d/%d resolver queries", host,
		countSuccessful(dnsResult.Observations), len(dnsResult.Observations))
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}

func detectDisagreement(answersByKey map[resolverRecordKey][]string) *types.Finding {
	perType := map[string]map[string]struct{}{}
	perTypeResolvers := map[string]map[string][]string{}

	for key, answers := range answersByKey {
		set := perType[key.RecordType]
		if set == nil {
			set = map[string]struct{}{}
			perType[key.RecordType] = set
		}
		if perTypeResolvers[key.RecordType] == nil {
			perTypeResolvers[key.RecordType] = map[string][]string{}
		}
		for _, a := range answers {
			set[a] = struct{}{}
		}
		perTypeResolvers[key.RecordType][key.Resolver] = answers
	}

	for rtype, set := range perType {
		if len(set) > 1 {
			return &types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerDNS,
				Title:    fmt.Sprintf("Resolvers disagree on %s records", rtype),
				Description: "Different DNS resolvers returned different answers for the same query. " +
					"This is expected briefly during a DNS change, but persisting disagreement can indicate " +
					"stale caching, split-horizon misconfiguration, or a propagation issue.",
				Evidence: map[string]interface{}{"answersByResolver": perTypeResolvers[rtype]},
				Owner:    types.OwnerDNSProvider,
			}
		}
	}
	return nil
}

func countSuccessful(obs []network.DNSObservation) int {
	n := 0
	for _, o := range obs {
		if o.Err == "" && len(o.Answers) > 0 {
			n++
		}
	}
	return n
}
