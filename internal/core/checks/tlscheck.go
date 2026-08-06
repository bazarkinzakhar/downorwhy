package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

// TLSExpiryWarningWindow is the threshold below which an unexpired
// certificate is flagged as expiring soon.
const TLSExpiryWarningWindow = 30

// TLSObserver is implemented by *network.TLSClient and by test doubles.
type TLSObserver interface {
	Observe(ctx context.Context, host, hostPort string) (*network.TLSObservation, error)
	ProbeLegacyProtocol(ctx context.Context, host, hostPort string) *bool
}

// RunTLS performs a TLS handshake against hostPort (using host for SNI and
// hostname verification) and evaluates the result for expiry, hostname
// mismatch, trust and protocol posture.
func RunTLS(ctx context.Context, host, hostPort string, observer TLSObserver) types.CheckResult {
	start := time.Now()
	result := types.NewCheckResult(types.CheckTLS)
	result.Status = types.CheckStatusPass

	obs, err := observer.Observe(ctx, host, hostPort)
	if err != nil {
		result.Status = types.CheckStatusError
		result.Error = err.Error()
		result.Summary = "could not establish a TCP connection to attempt a TLS handshake"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	result.Set("serverName", obs.ServerName)
	result.Set("negotiated", obs.Negotiated)

	if !obs.Negotiated {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerTLS,
			Title:    "TLS handshake failed",
			Description: "The server accepted a TCP connection but the TLS handshake did not complete. " +
				"This usually means the server is not serving TLS on this port, has a corrupted certificate " +
				"configuration, or is actively resetting the connection during negotiation.",
			Evidence: map[string]interface{}{"handshakeError": obs.HandshakeError},
			Owner:    types.OwnerHostingProvider,
		})
		result.Summary = "TLS handshake failed"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	result.Set("protocol", obs.Protocol)
	result.Set("cipherSuite", obs.CipherSuite)
	result.Set("peerCertificates", obs.PeerCertificates)
	result.Set("chainVerified", obs.ChainVerified)
	result.Set("daysUntilExpiry", obs.DaysUntilExpiry)

	switch {
	case obs.Expired:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate has expired",
			Description: fmt.Sprintf("The certificate expired %d day(s) ago. Browsers and API clients "+
				"will refuse this connection outright until it is renewed.", -obs.DaysUntilExpiry),
			Evidence: map[string]interface{}{"daysExpired": -obs.DaysUntilExpiry},
			Owner:    types.OwnerDevOps,
		})
	case obs.NotYetValid:
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate is not yet valid",
			Description: "The certificate's validity period has not started yet. This is usually caused " +
				"by a clock skew on the server or a misissued certificate.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerDevOps,
		})
	case obs.DaysUntilExpiry <= TLSExpiryWarningWindow:
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate expires soon",
			Description: fmt.Sprintf("The certificate expires in %d day(s). Renew it before expiry to "+
				"avoid an unplanned outage.", obs.DaysUntilExpiry),
			Evidence: map[string]interface{}{"daysUntilExpiry": obs.DaysUntilExpiry},
			Owner:    types.OwnerDevOps,
		})
	}

	if !obs.HostnameMatches {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate does not match the host name",
			Description: "The certificate presented by the server does not cover the requested host " +
				"name. Clients will reject this connection even though the handshake itself completes.",
			Evidence: map[string]interface{}{"hostnameError": obs.HostnameError, "host": obs.ServerName},
			Owner:    types.OwnerDevOps,
		})
	}

	if obs.SelfSigned {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate is self-signed",
			Description: "The certificate is signed by itself rather than by a certificate authority. " +
				"Browsers and most HTTP clients will show a trust warning or refuse the connection unless " +
				"it is explicitly trusted by the client.",
			Evidence: map[string]interface{}{},
			Owner:    types.OwnerDevOps,
		})
	} else if !obs.ChainVerified && !obs.Expired && !obs.NotYetValid {
		result.AddFinding(types.Finding{
			Severity: types.SeverityCritical,
			Layer:    types.LayerTLS,
			Title:    "TLS certificate chain does not verify",
			Description: "The certificate chain could not be verified against a trusted root. This " +
				"usually means an intermediate certificate is missing from the server's TLS configuration.",
			Evidence: map[string]interface{}{"chainVerifyError": obs.ChainVerifyError},
			Owner:    types.OwnerDevOps,
		})
	}

	if isWeakTLSProtocol(obs.Protocol) {
		result.AddFinding(types.Finding{
			Severity: types.SeverityWarning,
			Layer:    types.LayerTLS,
			Title:    fmt.Sprintf("Negotiated protocol %s is deprecated", obs.Protocol),
			Description: "The connection negotiated a TLS version older than 1.2. Deprecated protocol " +
				"versions have known weaknesses and are being removed from modern browsers and HTTP clients.",
			Evidence: map[string]interface{}{"protocol": obs.Protocol},
			Owner:    types.OwnerDevOps,
		})
	}

	if legacy := observer.ProbeLegacyProtocol(ctx, host, hostPort); legacy != nil {
		result.Set("legacyTlsAccepted", *legacy)
		if *legacy {
			result.AddFinding(types.Finding{
				Severity: types.SeverityWarning,
				Layer:    types.LayerTLS,
				Title:    "Server still accepts TLS 1.0",
				Description: "In addition to negotiating a modern protocol by default, the server also " +
					"accepts connections that request only TLS 1.0. Disabling legacy protocol versions " +
					"reduces exposure to downgrade attacks.",
				Evidence: map[string]interface{}{},
				Owner:    types.OwnerDevOps,
			})
		}
	}

	result.Summary = fmt.Sprintf("negotiated %s, chain verified: %v, expires in %d day(s)",
		obs.Protocol, obs.ChainVerified, obs.DaysUntilExpiry)
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}

func isWeakTLSProtocol(protocol string) bool {
	return protocol == "TLS 1.0" || protocol == "TLS 1.1"
}
