package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Special-purpose ranges are taken from IANA's IPv4/IPv6 registries:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// IPv6 probes require currently allocated global-unicast address space and
// exclude translation/tunnel ranges which could hide a private destination.
var certificateNonPublicNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var certificatePublicSpecialNetworks = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"), netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"), netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"), netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"), netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

var certificateGlobalIPv6 = netip.MustParsePrefix("2000::/3")

func certificatePublicIP(address netip.Addr) bool {
	if address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	if address.Is6() && !certificateGlobalIPv6.Contains(address) {
		return false
	}
	for _, prefix := range certificatePublicSpecialNetworks {
		if prefix.Contains(address) {
			return true
		}
	}
	for _, prefix := range certificateNonPublicNetworks {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func certificateProbeDialer() *net.Dialer {
	return &net.Dialer{Timeout: certificateProbeTimeout, ControlContext: func(_ context.Context, _ string, target string, _ syscall.RawConn) error {
		// This sees the actual resolved socket destination, so another DNS
		// answer or DNS rebinding cannot turn a public probe into a local one.
		address, err := netip.ParseAddrPort(target)
		if err != nil || !certificatePublicIP(address.Addr()) {
			return errors.New("DNS test requires a public destination IP")
		}
		return nil
	}}
}
