package url_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func TestPolicyCheckAddrBlocked(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "ipv4 unspecified", addr: "0.0.0.0"},
		{name: "ipv4 loopback", addr: "127.0.0.1"},
		{name: "ipv4 loopback range", addr: "127.99.10.20"},
		{name: "ipv4 private class a", addr: "10.0.0.1"},
		{name: "ipv4 private class b", addr: "172.16.0.1"},
		{name: "ipv4 private class c", addr: "192.168.1.1"},
		{name: "carrier grade nat", addr: "100.64.0.1"},
		{name: "ipv4 link local", addr: "169.254.10.10"},
		{name: "aws metadata", addr: "169.254.169.254"},
		{name: "aws ecs metadata", addr: "169.254.170.2"},
		{name: "alibaba metadata", addr: "100.100.100.200"},
		{name: "oracle metadata", addr: "192.0.0.192"},
		{name: "ipv4 multicast", addr: "224.0.0.1"},
		{name: "ipv4 documentation", addr: "192.0.2.1"},
		{name: "ipv4 benchmarking", addr: "198.18.0.1"},
		{name: "ipv4 future reserved", addr: "240.0.0.1"},
		{name: "ipv4 broadcast", addr: "255.255.255.255"},
		{name: "ipv6 unspecified", addr: "::"},
		{name: "ipv6 loopback", addr: "::1"},
		{name: "ipv6 unique local", addr: "fd00::1"},
		{name: "ipv6 link local", addr: "fe80::1"},
		{name: "ipv6 multicast", addr: "ff02::1"},
		{name: "ipv6 documentation", addr: "2001:db8::1"},
		{name: "ipv6 aws metadata", addr: "fd00:ec2::254"},
		{name: "nat64 well known prefix", addr: "64:ff9b::a00:1"},
		{name: "ipv4 mapped loopback", addr: "::ffff:127.0.0.1"},
		{name: "ipv4 mapped private", addr: "::ffff:10.0.0.1"},
	}

	policy := dowurl.DefaultPolicy()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)

			err := policy.CheckAddr(addr)

			require.ErrorIs(t, err, types.ErrUnsafeTarget)
			require.NotEmpty(t, dowurl.ReasonFor(addr))
		})
	}
}

func TestPolicyCheckAddrAllowed(t *testing.T) {
	addresses := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}

	policy := dowurl.DefaultPolicy()

	for _, raw := range addresses {
		t.Run(raw, func(t *testing.T) {
			addr := netip.MustParseAddr(raw)

			require.NoError(t, policy.CheckAddr(addr))
			require.Empty(t, dowurl.ReasonFor(addr))
		})
	}
}

func TestPolicyAllowPrivateTargets(t *testing.T) {
	policy := dowurl.Policy{AllowPrivate: true}

	require.NoError(t, policy.CheckAddr(netip.MustParseAddr("127.0.0.1")))
	require.NoError(t, policy.CheckAddr(netip.MustParseAddr("10.1.2.3")))
	require.NoError(t, policy.CheckAddr(netip.MustParseAddr("169.254.169.254")))
	require.NoError(t, policy.CheckHost("localhost"))
}

func TestPolicyCheckHostBlocked(t *testing.T) {
	hosts := []string{
		"localhost",
		"LOCALHOST",
		"api.localhost",
		"machine.local",
		"service.internal",
		"host.localdomain",
		"metadata.google.internal",
		"instance.metadata.google.internal",
		"vault.service.consul",
		"example.onion",
		"single-label-host",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"::1",
	}

	policy := dowurl.DefaultPolicy()

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			err := policy.CheckHost(host)
			require.ErrorIs(t, err, types.ErrUnsafeTarget)
		})
	}
}

func TestPolicyCheckHostAllowed(t *testing.T) {
	hosts := []string{
		"example.com",
		"api.example.co.uk",
		"xn--e1afmkfd.xn--p1ai",
		"1.1.1.1",
		"2606:4700:4700::1111",
	}

	policy := dowurl.DefaultPolicy()

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			require.NoError(t, policy.CheckHost(host))
		})
	}
}

func TestPolicyCheckTarget(t *testing.T) {
	policy := dowurl.DefaultPolicy()

	safeTarget, err := dowurl.Normalize("https://example.com/")
	require.NoError(t, err)
	require.NoError(t, policy.CheckTarget(safeTarget))

	privateTarget, err := dowurl.Normalize("http://127.0.0.1:8080/")
	require.NoError(t, err)
	require.ErrorIs(t, policy.CheckTarget(privateTarget), types.ErrUnsafeTarget)
}

func TestPolicyCheckRedirect(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{
			name:   "public https target",
			rawURL: "https://example.com/next",
		},
		{
			name:    "localhost target",
			rawURL:  "http://localhost:8080/",
			wantErr: true,
		},
		{
			name:    "private ipv4 target",
			rawURL:  "http://192.168.1.5/admin",
			wantErr: true,
		},
		{
			name:    "cloud metadata target",
			rawURL:  "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "ipv6 loopback target",
			rawURL:  "http://[::1]:8080/",
			wantErr: true,
		},
	}

	policy := dowurl.DefaultPolicy()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := dowurl.Normalize(tc.rawURL)
			require.NoError(t, err)

			err = policy.CheckRedirect(target)

			if tc.wantErr {
				require.ErrorIs(t, err, types.ErrUnsafeTarget)
				return
			}
			require.NoError(t, err)
		})
	}
}
