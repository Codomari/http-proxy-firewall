package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestCertificatePublicIPRejectsSpecialUseAddresses(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "127.0.0.2",
		"169.254.1.1", "172.16.0.1", "192.0.0.8", "192.0.2.1", "192.168.1.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:192.168.0.1", "64:ff9b::7f00:1",
		"100::1", "2001:2::1", "2001:db8::1", "2002:7f00:1::", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
		"2001:4860:4860::8888%zone",
	} {
		if certificatePublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("accepted non-public IP %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !certificatePublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("rejected public IP %s", raw)
		}
	}
	if certificatePublicIP(netip.Addr{}) {
		t.Fatal("accepted invalid IP")
	}
}

func TestCertificateProbeChecksActualSocketDestination(t *testing.T) {
	dialer := certificateProbeDialer()
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "2001:db8::1"} {
		if err := dialer.ControlContext(context.Background(), "tcp", net.JoinHostPort(raw, "80"), nil); err == nil {
			t.Errorf("allowed connection to %s", raw)
		}
	}
	if err := dialer.ControlContext(context.Background(), "tcp", "8.8.8.8:80", nil); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	g := testCertificateGuard(t)
	if response, err := g.client.Head(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("probe trusted loopback HTTP response")
	}
	if calls.Load() != 0 {
		t.Fatal("loopback endpoint was contacted")
	}
}
