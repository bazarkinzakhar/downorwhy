package checks

import (
	"fmt"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func RunIPv46(dnsResult network.DNSResult, response *network.Response) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckIPv46)

	var ipv4, ipv6 bool
	for _, obs := range dnsResult.Observations {
		if len(obs.Answers) == 0 {
			continue
		}
		switch obs.RecordType {
		case "A":
			ipv4 = true
		case "AAAA":
			ipv6 = true
		}
	}

	result.Set("hasA", ipv4)
	result.Set("hasAAAA", ipv6)

	switch {
	case !ipv4 && !ipv6:
		result.AddFinding(types.Finding{
			Severity:    types.SeverityCritical,
			Layer:       types.LayerDNS,
			Title:       "No A or AAAA records found",
			Description: "The domain has no IPv4 or IPv6 address records. The site is unreachable over any IP protocol.",
			Owner:       types.OwnerDNSProvider,
		})
	case !ipv4:
		result.AddFinding(types.Finding{
			Severity:    types.SeverityInfo,
			Layer:       types.LayerDNS,
			Title:       "No IPv4 (A) record",
			Description: "The domain advertises only IPv6. Clients on IPv4-only networks will not reach this site.",
			Owner:       types.OwnerDNSProvider,
		})
	case !ipv6:
		result.AddFinding(types.Finding{
			Severity:    types.SeverityInfo,
			Layer:       types.LayerDNS,
			Title:       "No IPv6 (AAAA) record",
			Description: "The domain does not advertise an IPv6 address. Clients on IPv6-only networks require a NAT64 gateway.",
			Owner:       types.OwnerDNSProvider,
		})
	default:
		result.Status = types.CheckStatusPass
	}

	if response != nil && response.RemoteAddr.IsValid() {
		family := "IPv4"
		if response.RemoteAddr.Is6() {
			family = "IPv6"
		}
		result.Set("connectedVia", family)
	}

	result.Summary = fmt.Sprintf("IPv4: %v, IPv6: %v", ipv4, ipv6)
	result.DurationMS = time.Since(start).Milliseconds()

	return result
}
