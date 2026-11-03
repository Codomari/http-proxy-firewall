package firewall

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
)

type clientIPKey struct{}

// ClientIP is the address verified by this firewall's proxy trust policy.
// Values kept in Locals own their storage and are valid through this handler.
func ClientIP(c fiber.Ctx) string {
	if ip, ok := c.Locals(clientIPKey{}).(netip.Addr); ok {
		return ip.String()
	}
	return c.RequestCtx().RemoteIP().String()
}

// ResolveClientIP applies the same proxy trust policy before firewall admission,
// allowing debug logging to include requests that admission or inspection rejects.
func (e *Engine) ResolveClientIP(c fiber.Ctx) string {
	return e.clientAddress(c).String()
}

// Resolve once so changing a hostname setting during a request cannot make
// debug filtering, firewall decisions and upstream forwarding disagree.
func (e *Engine) clientAddress(c fiber.Ctx) netip.Addr {
	if address, ok := c.Locals(clientIPKey{}).(netip.Addr); ok {
		return address
	}
	address := e.resolveClient(c)
	c.Locals(clientIPKey{}, address)
	return address
}

func normalizeHostname(raw string) (string, error) {
	host, err := CanonicalHostname(raw)
	if err != nil {
		return "", err
	}
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return "", errors.New("invalid hostname")
	}
	return host, nil
}

// CanonicalHostname preserves www so dashboard hosts remain distinct. The
// firewall's cookie/detector normalization separately groups www and bare names.
func CanonicalHostname(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" || strings.ContainsAny(host, "\x00\r\n\t /\\@?#") {
		return "", errors.New("invalid hostname")
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		return normalizedAddressHost(parsed)
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		parsed, err := netip.ParseAddr(host[1 : len(host)-1])
		if err != nil {
			return "", errors.New("invalid IPv6 hostname")
		}
		return normalizedAddressHost(parsed)
	}
	if strings.Contains(host, ":") {
		name, port, err := net.SplitHostPort(host)
		if err != nil {
			return "", errors.New("invalid hostname port")
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n > 65535 {
			return "", errors.New("invalid hostname port")
		}
		host = name
		if parsed, err := netip.ParseAddr(host); err == nil {
			return normalizedAddressHost(parsed)
		}
	}
	host = strings.TrimSuffix(host, ".")
	// DNS presentation names fit 253 bytes without their optional final dot.
	// Check before removing www so an oversized authority cannot become valid
	// merely because the firewall groups www and its bare hostname together.
	if len(host) > 253 {
		return "", errors.New("hostname exceeds 253 bytes")
	}
	host = strings.ToLower(host)
	if len(host) > 253 { // Some Unicode case mappings increase the byte length.
		return "", errors.New("hostname exceeds 253 bytes")
	}
	if host == "" || strings.ContainsAny(host, ":[]") {
		return "", errors.New("invalid hostname")
	}
	return host, nil
}

func normalizedAddressHost(address netip.Addr) (string, error) {
	// Interface zones identify a scope on one machine and cannot form a stable
	// proxy hostname. netip permits arbitrarily long zones, so reject them in
	// every IP fast path instead of bypassing the DNS retention bound.
	if address.Zone() != "" {
		return "", errors.New("IPv6 zones are not allowed in hostnames")
	}
	return address.Unmap().String(), nil
}

func containsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (e *Engine) resolveClient(c fiber.Ctx) netip.Addr {
	peer, _ := netip.AddrFromSlice(c.RequestCtx().RemoteIP())
	peer = peer.Unmap()
	behindCloudflare, configured := e.cloudflare.match(string(c.Request().Header.Host()))
	if behindCloudflare && containsAddress(cloudflareNetworks, peer) {
		if address, ok := cloudflareClient(c); ok {
			return address
		}
		return peer
	}
	if !containsAddress(e.trustedProxies, peer) {
		return peer
	}
	if behindCloudflare || e.trustCloudflare && !configured {
		if address, ok := cloudflareClient(c); ok {
			return address
		}
	}
	values := c.Request().Header.PeekAll("X-Forwarded-For")
	current := peer
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(string(values[i]), ",")
		for j := len(parts) - 1; j >= 0; j-- {
			if !containsAddress(e.trustedProxies, current) {
				return current
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				return peer
			}
			current = ip.Unmap()
		}
	}
	if len(values) == 0 {
		if ip, err := netip.ParseAddr(strings.TrimSpace(c.Get("X-Real-IP"))); err == nil {
			return ip.Unmap()
		}
	}
	return current
}

func parseNetworks(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, errors.New("invalid IP address or network: " + value)
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}
