package checks_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/checks"
	"github.com/downorwhy/downorwhy/internal/core/network"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

type fakeTLSObserver struct {
	obs    *network.TLSObservation
	err    error
	legacy *bool
}

func (f fakeTLSObserver) Observe(context.Context, string, string) (*network.TLSObservation, error) {
	return f.obs, f.err
}

func (f fakeTLSObserver) ProbeLegacyProtocol(context.Context, string, string) *bool {
	return f.legacy
}

func boolPtr(b bool) *bool { return &b }

func healthyObservation() *network.TLSObservation {
	return &network.TLSObservation{
		Negotiated:      true,
		Protocol:        "TLS 1.3",
		CipherSuite:     "TLS_AES_128_GCM_SHA256",
		ServerName:      "example.com",
		HostnameMatches: true,
		ChainVerified:   true,
		DaysUntilExpiry: 120,
	}
}

func TestRunTLSDialErrorProducesErrorStatus(t *testing.T) {
	observer := fakeTLSObserver{err: types.NewScanError(types.LayerTLS, "dial", types.ErrUnreachable)}
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", observer)
	require.Equal(t, types.CheckStatusError, result.Status)
	require.NotEmpty(t, result.Error)
	require.Empty(t, result.Findings)
}

func TestRunTLSHandshakeFailureIsCritical(t *testing.T) {
	observer := fakeTLSObserver{obs: &network.TLSObservation{
		Negotiated:     false,
		ServerName:     "example.com",
		HandshakeError: "tls: first record does not look like a TLS handshake",
	}}
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", observer)
	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, types.SeverityCritical, result.Findings[0].Severity)
	require.Equal(t, types.OwnerHostingProvider, result.Findings[0].Owner)
}

func TestRunTLSExpiredCertificateIsCritical(t *testing.T) {
	obs := healthyObservation()
	obs.Expired = true
	obs.ChainVerified = false
	obs.DaysUntilExpiry = -5

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "TLS certificate has expired", result.Findings[0].Title)
	require.Contains(t, result.Findings[0].Description, "5 day")
}

func TestRunTLSExpiringSoonIsWarning(t *testing.T) {
	obs := healthyObservation()
	obs.DaysUntilExpiry = 10

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusWarn, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "TLS certificate expires soon", result.Findings[0].Title)
}

func TestRunTLSHostnameMismatchIsCritical(t *testing.T) {
	obs := healthyObservation()
	obs.HostnameMatches = false
	obs.HostnameError = "certificate is valid for other.example, not example.com"

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "TLS certificate does not match the host name", result.Findings[0].Title)
}

func TestRunTLSSelfSignedIsWarningNotAlsoChainFailure(t *testing.T) {
	obs := healthyObservation()
	obs.SelfSigned = true
	obs.ChainVerified = false

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusWarn, result.Status)
	require.Len(t, result.Findings, 1, "self-signed and untrusted-chain must not be reported as two separate findings")
	require.Equal(t, "TLS certificate is self-signed", result.Findings[0].Title)
}

func TestRunTLSUnknownCAChainFailureIsCritical(t *testing.T) {
	obs := healthyObservation()
	obs.SelfSigned = false
	obs.ChainVerified = false
	obs.ChainVerifyError = "x509: certificate signed by unknown authority"

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusFail, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "TLS certificate chain does not verify", result.Findings[0].Title)
	require.Equal(t, types.SeverityCritical, result.Findings[0].Severity)
}

func TestRunTLSWeakProtocolIsWarning(t *testing.T) {
	obs := healthyObservation()
	obs.Protocol = "TLS 1.1"

	result := checks.RunTLS(context.Background(), "example.com", "example.com:443", fakeTLSObserver{obs: obs})
	require.Equal(t, types.CheckStatusWarn, result.Status)
	require.Len(t, result.Findings, 1)
	require.Contains(t, result.Findings[0].Title, "deprecated")
}

func TestRunTLSLegacyProtocolAcceptedIsWarning(t *testing.T) {
	obs := healthyObservation()
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443",
		fakeTLSObserver{obs: obs, legacy: boolPtr(true)})
	require.Equal(t, types.CheckStatusWarn, result.Status)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "Server still accepts TLS 1.0", result.Findings[0].Title)
}

func TestRunTLSLegacyProtocolRejectedProducesNoFinding(t *testing.T) {
	obs := healthyObservation()
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443",
		fakeTLSObserver{obs: obs, legacy: boolPtr(false)})
	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
}

func TestRunTLSLegacyProtocolNotProbedIsOmittedFromDetails(t *testing.T) {
	obs := healthyObservation()
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443",
		fakeTLSObserver{obs: obs, legacy: nil})
	_, ok := result.Details["legacyTlsAccepted"]
	require.False(t, ok, "an unprobed legacy protocol result must not be reported as a known false")
}

func TestRunTLSHealthyCertificateProducesNoFindings(t *testing.T) {
	obs := healthyObservation()
	result := checks.RunTLS(context.Background(), "example.com", "example.com:443",
		fakeTLSObserver{obs: obs, legacy: boolPtr(false)})
	require.Equal(t, types.CheckStatusPass, result.Status)
	require.Empty(t, result.Findings)
	require.Contains(t, result.Summary, "TLS 1.3")
}
