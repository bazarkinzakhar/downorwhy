package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// DNSSlowThreshold flags a resolver as slow above this latency.
const DNSSlowThreshold = 500 * time.Millisecond

// RunDNS resolves host through resolver and evaluates the answers for
// outages, cross-resolver disagreement and latency. resolver is an interface
// so production code injects network.DNSClient and tests inject a fake.
func RunDNS(ctx context.Context, host string, resolver network.Resolver) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckDNS)
	result.Status = types.CheckStatusPass

	dnsResult := resolver.Resolve(ctx, host)

	var (
		anyAnswer       bool
		slowQueries     []string
		failedQueries   []string
		validatedByAny  bool
		ipv4Present     bool
		ipv6Present     bool
		answersByRecord = map[string]map[string][]string{}
	)

	for _, obs := range dnsResult.Observations {
		if len(obs.Answers) > 0 {
			anyAnswer = true

			if answersByRecord[obs.RecordType] == nil {
				answersByRecord[obs.RecordType] = map[string][]string{}
			}
			answersByRecord[obs.RecordType][string(obs.Resolver)] = normalizedAnswers(obs.Answers)

			switch obs.RecordType {
			case "A":
				ipv4Present = true
			case "AAAA":
				ipv6Present = true
			}
		}

		if obs.Err != "" {
			failedQueries = append(failedQueries, fmt.Sprintf("%s/%s: %s", obs.Resolver, obs.RecordType, obs.Err))
		}

		if time.Duration(obs.LatencyMS)*time.Millisecond > DNSSlowThreshold {
			slowQueries = append(slowQueries, fmt.Sprintf("%s/%s (%dms)", obs.Resolver, obs.RecordType, obs.LatencyMS))
		}

		if obs.DNSSECValidated {
			validatedByAny = true
		}
	}

	result.Set("host", host)
	result.Set("observations", dnsResult.Observations)
	result.Set("hasIPv4", ipv4Present)
	result.Set("hasIPv6", ipv6Present)
	result.Set("dnssecValidatedByAnyResolver", validatedByAny)

	if !anyAnswer {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerDNS,
			Title:    "Domain does not resolve",
			Description: "No resolver returned an A or AAAA record for this host. The domain either " +
				"has no DNS records, does not exist, or every queried resolver failed independently. " +
				"Nothing else about the site can be reached until this is fixed.",
			Evidence: map[string]interface{}{
				"observations": dnsResult.Observations,
			},
			Owner: types.OwnerDNSProvider,
		})

		result.Status = types.CheckStatusFail
		result.Summary = "no resolver returned an address for " + host
		result.DurationMS = time.Since(start).Milliseconds()

		return result
	}

	if len(failedQueries) > 0 {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerDNS,
			Title:    "One or more DNS resolvers failed",
			Description: "At least one resolver returned an error while others succeeded. This can " +
				"indicate resolver-specific blocking, propagation lag, or an intermittent authoritative " +
				"nameserver. Users of the affected resolver may not reach the site.",
			Evidence: map[string]interface{}{
				"failedQueries": failedQueries,
			},
			Owner: types.OwnerDNSProvider,
		})
	}

	if len(slowQueries) > 0 {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerDNS,
			Title:    "Slow DNS resolution",
			Description: fmt.Sprintf("DNS lookups took longer than %s. Slow DNS delays every "+
				"connection to this site, including the first byte of every page load.", DNSSlowThreshold),
			Evidence: map[string]interface{}{
				"slowQueries": slowQueries,
			},
			Owner: types.OwnerDNSProvider,
		})
	}

	for _, recordType := range sortedKeys(answersByRecord) {
		if finding := disagreementFinding(recordType, answersByRecord[recordType]); finding != nil {
			result.AddFinding(*finding)
		}
	}

	result.Summary = fmt.Sprintf(
		"resolved %s: %d of %d resolver queries returned records",
		host,
		countSuccessful(dnsResult.Observations),
		len(dnsResult.Observations),
	)
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}

// disagreementFinding reports a finding when two resolvers returned different
// answer sets for the same record type. Order and duplicates are ignored: two
// resolvers returning the same two addresses in a different order agree.
func disagreementFinding(recordType string, byResolver map[string][]string) *types.Finding {
	if len(byResolver) < 2 {
		return nil
	}

	var reference string
	var referenceResolver string

	for _, resolverName := range sortedStringKeys(byResolver) {
		fingerprint := strings.Join(byResolver[resolverName], ",")

		if referenceResolver == "" {
			reference = fingerprint
			referenceResolver = resolverName
			continue
		}

		if fingerprint != reference {
			evidence := make(map[string]interface{}, len(byResolver))
			for name, answers := range byResolver {
				evidence[name] = answers
			}

			return &types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerDNS,
				Title:    fmt.Sprintf("Resolvers disagree on %s records", recordType),
				Description: "Different DNS resolvers returned different answers for the same query. " +
					"This is expected briefly during a DNS change, but persistent disagreement points to " +
					"stale caching, split-horizon configuration, or an incomplete propagation. Some users " +
					"will reach a different server than others.",
				Evidence: map[string]interface{}{
					"answersByResolver": evidence,
				},
				Owner: types.OwnerDNSProvider,
			}
		}
	}

	return nil
}

func normalizedAnswers(answers []string) []string {
	unique := make(map[string]struct{}, len(answers))
	for _, a := range answers {
		unique[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}

	out := make([]string, 0, len(unique))
	for a := range unique {
		out = append(out, a)
	}
	sort.Strings(out)

	return out
}

func sortedKeys(m map[string]map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)

	return out
}

func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)

	return out
}

func countSuccessful(observations []network.DNSObservation) int {
	n := 0
	for _, obs := range observations {
		if obs.Err == "" && len(obs.Answers) > 0 {
			n++
		}
	}

	return n
}
