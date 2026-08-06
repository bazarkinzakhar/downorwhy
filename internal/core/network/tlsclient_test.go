package network_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/network"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

type certOpts struct {
	commonName string
	dnsNames   []string
	notBefore  time.Time
	notAfter   time.Time
	isCA       bool
	parent     *x509.Certificate
	parentKey  *ecdsa.PrivateKey
}

func generateCertificate(t *testing.T, opts certOpts) ([][]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: opts.commonName,
		},
		DNSNames:              opts.dnsNames,
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}

	if opts.isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parentTemplate := template
	parentKey := key
	if opts.parent != nil {
		parentTemplate = opts.parent
		parentKey = opts.parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return [][]byte{der}, key, cert
}

func startTLSTestServer(
	t *testing.T,
	certChain [][]byte,
	key *ecdsa.PrivateKey,
	minVersion uint16,
) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: certChain,
				PrivateKey:  key,
			},
		},
		MinVersion: minVersion,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

func hostPortOf(srv *httptest.Server) string {
	return srv.Listener.Addr().String()
}

func testDialer(t *testing.T) *network.SafeDialer {
	t.Helper()
	return network.NewSafeDialer(dowurl.Policy{AllowPrivate: true}, nil, 5*time.Second)
}

func TestTLSClientObserveValidCAChain(t *testing.T) {
	now := time.Now()
	_, caKey, caCert := generateCertificate(t, certOpts{
		commonName: "Test CA",
		dnsNames:   nil,
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(48 * time.Hour),
		isCA:       true,
	})

	leafChain, leafKey, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(48 * time.Hour),
		isCA:       false,
		parent:     caCert,
		parentKey:  caKey,
	})

	srv := startTLSTestServer(t, leafChain, leafKey, tls.VersionTLS12)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   roots,
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.True(t, obs.Negotiated)
	require.True(t, obs.ChainVerified, obs.ChainVerifyError)
	require.False(t, obs.SelfSigned)
	require.True(t, obs.HostnameMatches)
	require.False(t, obs.Expired)
	require.Greater(t, obs.DaysUntilExpiry, 0)
}

func TestTLSClientObserveSelfSignedTrustedAsOwnRoot(t *testing.T) {
	now := time.Now()
	chain, key, cert := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   roots,
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.True(t, obs.SelfSigned)
	require.True(t, obs.ChainVerified, obs.ChainVerifyError)
}

func TestTLSClientObserveSelfSignedUntrusted(t *testing.T) {
	now := time.Now()
	chain, key, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   x509.NewCertPool(),
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.True(t, obs.SelfSigned)
	require.False(t, obs.ChainVerified)
	require.NotEmpty(t, obs.ChainVerifyError)
}

func TestTLSClientObserveExpiredCertificate(t *testing.T) {
	now := time.Now()
	chain, key, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-48 * time.Hour),
		notAfter:   now.Add(-24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   x509.NewCertPool(),
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.True(t, obs.Expired)
	require.False(t, obs.ChainVerified)
	require.Negative(t, obs.DaysUntilExpiry)
}

func TestTLSClientObserveNotYetValidCertificate(t *testing.T) {
	now := time.Now()
	chain, key, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(48 * time.Hour),
		notAfter:   now.Add(72 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   x509.NewCertPool(),
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.True(t, obs.NotYetValid)
}

func TestTLSClientObserveHostnameMismatch(t *testing.T) {
	now := time.Now()
	chain, key, cert := generateCertificate(t, certOpts{
		commonName: "other.example",
		dnsNames:   []string{"other.example"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   roots,
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.False(t, obs.HostnameMatches)
	require.NotEmpty(t, obs.HostnameError)
	require.True(t, obs.ChainVerified, obs.ChainVerifyError)
}

func TestTLSClientObserveHandshakeFailureAgainstPlaintextServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.False(t, obs.Negotiated)
	require.NotEmpty(t, obs.HandshakeError)
}

func TestTLSClientObserveDialRejectedForUnsafeTarget(t *testing.T) {
	now := time.Now()
	chain, key, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS12)

	unsafeDialer := network.NewSafeDialer(dowurl.DefaultPolicy(), nil, 5*time.Second)
	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  unsafeDialer,
		Timeout: 5 * time.Second,
	})

	_, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrUnsafeTarget)
}

func TestTLSClientProbeLegacyProtocolRejectedByServer(t *testing.T) {
	now := time.Now()
	chain, key, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	srv := startTLSTestServer(t, chain, key, tls.VersionTLS13)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
	})

	result := client.ProbeLegacyProtocol(context.Background(), "testhost", hostPortOf(srv))
	if result == nil {
		t.Skip("local Go runtime does not support negotiating TLS 1.0 client-side")
	}
	require.False(t, *result)
}

func TestTLSClientObserveMultipleCertificatesReported(t *testing.T) {
	now := time.Now()
	_, caKey, caCert := generateCertificate(t, certOpts{
		commonName: "Test CA",
		dnsNames:   nil,
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})

	leafChain, leafKey, _ := generateCertificate(t, certOpts{
		commonName: "testhost",
		dnsNames:   []string{"testhost"},
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       false,
		parent:     caCert,
		parentKey:  caKey,
	})

	srv := startTLSTestServer(t, leafChain, leafKey, tls.VersionTLS12)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	client := network.NewTLSClient(network.TLSClientOptions{
		Dialer:  testDialer(t),
		Timeout: 5 * time.Second,
		Roots:   roots,
	})

	obs, err := client.Observe(context.Background(), "testhost", hostPortOf(srv))
	require.NoError(t, err)
	require.Len(t, obs.PeerCertificates, 1)
	require.Equal(t, "CN=testhost", obs.PeerCertificates[0].Subject)
}

func TestSafeDialerRejectsPrivateAddress(t *testing.T) {
	dialer := network.NewSafeDialer(dowurl.DefaultPolicy(), nil, time.Second)
	_, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:9")
	require.Error(t, err)
	require.True(t, errors.Is(err, types.ErrUnsafeTarget))
}