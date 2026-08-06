func TestPolicyCheckAddrBlocked(t *testing.T) {
	tests := []struct{ name, addr string }{
		{"ipv4 loopback", "127.0.0.1"},
		{"ipv4 loopback alt", "127.1.2.3"},
		{"ipv6 loopback", "::1"},
		{"private 10", "10.0.0.1"},
		{"private 172.16", "172.16.5.5"},
		{"private 192.168", "192.168.1.1"},
		{"cgnat", "100.64.0.1"},
		{"link local", "169.254.10.10"},
		{"aws metadata", "169.254.169.254"},
		{"ecs metadata", "169.254.170.2"},
		{"alibaba metadata", "100.100.100.200"},
		{"oracle metadata", "192.0.0.192"},
		{"ipv6 ula", "fd00::1"},
		{"ipv6 link local", "fe80::1"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"broadcast", "255.255.255.255"},
		{"test-net-1", "192.0.2.1"},
		{"documentation v6", "2001:db8::1"},
		{"4in6 loopback bypass attempt", "::ffff:127.0.0.1"},
		{"4in6 private bypass attempt", "::ffff:10.0.0.1"},
		{"nat64 mapped", "64:ff9b::a00:1"},
	}
	p := url.DefaultPolicy()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			require.ErrorIs(t, p.CheckAddr(addr), types.ErrUnsafeTarget)
			require.NotEmpty(t, url.ReasonFor(addr))
		})
	}
}

func TestPolicyCheckAddrAllowed(t *testing.T) {
	p := url.DefaultPolicy()
	for _, s := range []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"} {
		require.NoError(t, p.CheckAddr(netip.MustParseAddr(s)), s)
	}
}
