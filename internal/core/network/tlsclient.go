package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// CertInfo is the report-facing summary of one certificate in a chain.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	DNSNames           []string  `json:"dnsNames"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SerialNumber       string    `json:"serialNumber"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	IsCA               bool      `json:"isCA"`
}

// TLSObservation is the full diagnostic result of one TLS handshake attempt.
// A completed but invalid handshake, such as an expired certificate or a
// hostname mismatch, is a normal fully populated observation rather than an
// error: describing exactly what is wrong is the purpose of this tool.
type TLSObservation struct {
	Negotiated       bool       `json:"negotiated"`
	Protocol         string     `json:"protocol,omitempty"`
	CipherSuite      string     `json:"cipherSuite,omitempty"`
	ServerName       string     `json:"serverName"`
	PeerCertificates []CertInfo `json:"peerCertificates,omitempty"`
	SelfSigned       bool       `json:"selfSigned"`
	HostnameMatches  bool       `json:"hostnameMatches"`
	HostnameError    string     `json:"hostnameError,omitempty"`
	Expired          bool       `json:"expired"`
	NotYetValid      bool       `json:"notYetValid"`
	DaysUntilExpiry  int        `json:"daysUntilExpiry"`
	ChainVerified    bool       `json:"chainVerified"`
	ChainVerifyError string     `json:"chainVerifyError,omitempty"`
	HandshakeError   string     `json:"handshakeError,omitempty"`
}

// TLSClient performs raw TLS handshakes for diagnosis. It deliberately does
// not rely on the standard verification performed by crypto/tls, because a
// single failed verification collapses several independently actionable
// problems, such as expiry, hostname mismatch and an untrusted issuer, into
// one opaque error. Each condition is evaluated separately here so the check
// package can name the real cause and route it to the right owner.
type TLSClient struct {
	dialer  *SafeDialer
	timeout time.Duration
	roots   *x509.CertPool
}

// TLSClientOptions configures a TLSClient.
type TLSClientOptions struct {
	Dialer  *SafeDialer
	Timeout time.Duration
	// Roots overrides the trust store used for chain verification. Nil uses
	// the platform trust store, matching what a browser would trust.
	Roots *x509.CertPool
}

// NewTLSClient builds a TLSClient.
func NewTLSClient(opts TLSClientOptions) *TLSClient {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	return &TLSClient{dialer: opts.Dialer, timeout: timeout, roots: opts.Roots}
}

// Observe performs a TLS handshake against hostPort, using host both as the
// SNI value and as the name checked against the certificate. It returns an
// error only when no TCP connection could be established at all, such as an
// SSRF rejection or a refused connection; every handshake-level problem is
// captured inside the returned observation.
func (c *TLSClient) Observe(ctx context.Context, host, hostPort string) (*TLSObservation, error) {
	if c.dialer == nil {
		return nil, fmt.Errorf("%w: TLS client was constructed without a dialer", types.ErrInternal)
	}

	conn, err := c.dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
		return nil, fmt.Errorf("%w: setting connection deadline: %s", types.ErrInternal, deadlineErr)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		// Verification is performed manually below so each failure mode can be
		// reported separately. This client never establishes trust.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic handshake, see comment above
		MinVersion:         tls.VersionTLS10,
	})

	observation := &TLSObservation{ServerName: host}

	if handshakeErr := tlsConn.HandshakeContext(ctx); handshakeErr != nil {
		observation.HandshakeError = handshakeErr.Error()
		return observation, nil
	}
	observation.Negotiated = true

	state := tlsConn.ConnectionState()
	observation.Protocol = protocolName(state.Version)
	observation.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) == 0 {
		observation.HandshakeError = "server presented no certificates"
		return observation, nil
	}

	for _, cert := range state.PeerCertificates {
		observation.PeerCertificates = append(observation.PeerCertificates, CertInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			DNSNames:           cert.DNSNames,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SerialNumber:       cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			IsCA:               cert.IsCA,
		})
	}

	leaf := state.PeerCertificates[0]
	now := time.Now()

	observation.SelfSigned = leaf.CheckSignatureFrom(leaf) == nil
	observation.Expired = now.After(leaf.NotAfter)
	observation.NotYetValid = now.Before(leaf.NotBefore)
	observation.DaysUntilExpiry = int(time.Until(leaf.NotAfter).Hours() / 24)

	if hostnameErr := leaf.VerifyHostname(host); hostnameErr != nil {
		observation.HostnameError = hostnameErr.Error()
	} else {
		observation.HostnameMatches = true
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	// DNSName is intentionally omitted: chain trust and hostname coverage are
	// separate problems with separate remedies, and merging them would report
	// one root cause as two conflicting findings.
	if _, verifyErr := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         c.roots,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); verifyErr != nil {
		observation.ChainVerifyError = verifyErr.Error()
	} else {
		observation.ChainVerified = true
	}

	return observation, nil
}

// ProbeLegacyProtocol attempts a handshake restricted to TLS 1.0 to determine
// whether the server still accepts a deprecated protocol version. A nil
// result means the probe could not be completed meaningfully, most commonly
// because this Go runtime refuses to offer TLS 1.0 at all, and must never be
// reported as either a pass or a failure.
func (c *TLSClient) ProbeLegacyProtocol(ctx context.Context, host, hostPort string) *bool {
	if c.dialer == nil {
		return nil
	}

	conn, err := c.dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
		return nil
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // probing accepted protocol versions, not establishing trust
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	})

	handshakeErr := tlsConn.HandshakeContext(ctx)
	if handshakeErr != nil && isLocalProtocolRefusal(handshakeErr) {
		return nil
	}

	accepted := handshakeErr == nil

	return &accepted
}

// isLocalProtocolRefusal reports whether err was raised by the local
// crypto/tls client before any bytes reached the network, which happens when
// the runtime disables TLS 1.0 client support. Such an error says nothing
// about the server and must be treated as "not probed".
func isLocalProtocolRefusal(err error) bool {
	message := err.Error()

	return strings.Contains(message, "protocol version not supported") ||
		strings.Contains(message, "no supported versions satisfy")
}

func protocolName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
