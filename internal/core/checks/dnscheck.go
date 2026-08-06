// Package checks contains one file per DownOrWhy check. Every check exposes a
// Run function with an identical signature so the scanner can invoke them
// uniformly; see docs/architecture.md.
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

// RunDNS resolves host across the system resolver and three DoH resolvers and
// evaluates the answers for outages, disagreement and DNSSEC issues.
func RunDNS(ctx context.Context, host string, client *network.DNSClient) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckDNS)
	result.Status = types.CheckStatusPass

	dnsResult := client.Resolve(ctx, host)

	bySeenSet := map[ResolverKey][]string{}
	anyAnswer := false
	var slowResolvers []string
	var failedResolvers []string

	for _, obs := range dnsResult.Observations {
		key := ResolverKey{Resolver: string(obs.Resolver), RecordType: obs.RecordType}
		if len(obs.Answers) > 0 {
			anyAnswer = true
			bySeenSet[key] = append(bySeenSet[key], obs.Answers...)
		}
		if obs.Err != "" || (obs.RCode != "" && obs.RCode != "NOERROR") {
			failedResolvers = append(failedResolvers, fmt.Sprintf("%s/%s", obs.Resolver, obs.RecordType))
		}
		if time.Duration(obs.LatencyMS)*time.Millisecond > DNSSlowThreshold {
			slowResolvers = append(slowResolvers, fmt.Sprintf("%s/%s (%dms)", obs.Resolver, obs.RecordType, obs.LatencyMS))
		}
	}

	result.Set("host", host)
	result.Set("observations", dnsResult.Observations)

	if !anyAnswer {
		result.AddFinding(types.Finding{
			Severity:    types.SeverityCritical,
			Layer:       types.LayerDNS,
			Title:       "Domain does not resolve",
			Description: "No resolver returned an A or AAAA record for this host. The domain either does not exist, has no DNS records, or every queried resolver failed independently.",
			Evidence:    map[string]interface{}{"observations": dnsResult.Observations},
			Owner:       types.OwnerDNSProvider,
		})
		result.Status = types.CheckStatusFail
		result.Summary = "no resolver returned an address for " + host
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	if len(failedResolvers) > 0 {
		result.AddFinding(types.Finding{
			Severity:    types.SeverityWarning,
			Layer:       types.LayerDNS,
			Title:       "One or more DNS resolvers failed",
			Description: "At least one resolver returned an error or non-success response code while others succeeded. This can indicate resolver-specific blocking, propagation lag, or an intermittent authoritative nameserver issue.",
			Evidence:    map[string]interface{}{"failedQueries": failedResolvers},
			Owner:       types.OwnerDNSProvider,
		})
	}

	if len(slowResolvers) > 0 {
		result.AddFinding(types.Finding{
			Severity:    types.SeverityWarning,
			Layer:       types.LayerDNS,
			Title:       "Slow DNS resolution",
			Description: fmt.Sprintf("DNS lookups took longer than %s. Slow DNS delays every subsequent connection to this site.", DNSSlowThreshold),
			Evidence:    map[string]interface{}{"slowQueries": slowResolvers},
			Owner:       types.OwnerDNSProvider,
		})
	}

	if disagreement := detectDisagreement(bySeenSet); disagreement != nil {
		result.AddFinding(*disagreement)
	}

	result.Summary = fmt.Sprintf("resolved %s via %d/%d resolver queries", host, countSuccessful(dnsResult.Observations), len(dnsResult.Observations))
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}

// ResolverKey groups observations by resolver and record type so answer sets
// can be compared for disagreement.
type ResolverKey struct {
	Resolver   string
	RecordType string
}

func detectDisagreement(bySeenSet map[ResolverKey][]string) *types.Finding {
	perType := map[string]map[string]struct{}{}
	perTypeResolvers := map[string]map[string][]string{}
	for key, answers := range bySeenSet {
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
			f := types.Finding{
				Severity:    types.SeverityWarning,
				Layer:       types.LayerDNS,
				Title:       fmt.Sprintf("Resolvers disagree on %s records", rtype),
				Description: "Different DNS resolvers returned different answers for the same query. This is expected briefly during a DNS change, but persisting disagreement can indicate stale caching, split-horizon misconfiguration, or a propagation issue.",
				Evidence:    map[string]interface{}{"answersByResolver": perTypeResolvers[rtype]},
				Owner:       types.OwnerDNSProvider,
			}
			return &f
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
