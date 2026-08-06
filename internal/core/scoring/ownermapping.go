package scoring

import "github.com/downorwhy/downorwhy/internal/core/types"

// OwnerMapping maps a finding to an owner. The finding already carries an
// owner set by the check; this function exists for cross-cutting overrides
// and for the recommendations generator.
func OwnerDisplay(owner string) string {
	switch owner {
	case types.OwnerDNSProvider:
		return "DNS provider"
	case types.OwnerHostingProvider:
		return "Hosting provider"
	case types.OwnerDevOps:
		return "DevOps / platform team"
	case types.OwnerBackend:
		return "Backend engineering"
	case types.OwnerFrontend:
		return "Frontend engineering"
	case types.OwnerSecurity:
		return "Security team"
	case types.OwnerUser:
		return "Site owner"
	default:
		return owner
	}
}
