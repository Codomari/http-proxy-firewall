// Package ipfirewall maintains provider networks outside the request path.
package ipfirewall

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

const MaxCustomNetworks = 512

// NormalizeSettings validates selections and accepts individual IPs or CIDRs.
func NormalizeSettings(providers, networks []string) ([]string, []string, error) {
	if len(providers) > len(catalog) || len(networks) > MaxCustomNetworks {
		return nil, nil, errors.New("IP Firewall supports at most 512 custom entries and one selection per provider")
	}
	selected, entries := []string{}, []string{}
	seen := map[string]bool{}
	for _, raw := range providers {
		id := strings.ToLower(strings.TrimSpace(raw))
		if !knownProvider(id) {
			return nil, nil, errors.New("unknown IP Firewall provider")
		}
		if !seen[id] {
			seen[id] = true
			selected = append(selected, id)
		}
	}
	seen = map[string]bool{}
	for _, raw := range networks {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := parsePrefix(raw)
		if err != nil {
			return nil, nil, errors.New("IP Firewall entries must be IPv4/IPv6 addresses or CIDR subnets without zones")
		}
		value := prefix.String()
		if !strings.Contains(raw, "/") {
			value = prefix.Addr().String()
		}
		if !seen[value] {
			seen[value] = true
			entries = append(entries, value)
		}
	}
	return selected, entries, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addrErr := netip.ParseAddr(value)
		if addrErr != nil || address.Zone() != "" {
			return netip.Prefix{}, errors.New("invalid IP or CIDR")
		}
		address = address.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New("invalid mapped CIDR")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

type interval struct{ start, end netip.Addr }

// Networks is immutable after construction. Merged intervals keep lookups
// logarithmic even when providers publish thousands of overlapping prefixes.
type Networks struct {
	v4, v6 []interval
}

func Compile(records []string) (*Networks, error) {
	result := &Networks{}
	for _, record := range records {
		prefix, err := parsePrefix(record)
		if err != nil {
			return nil, err
		}
		start := prefix.Addr()
		end := start.As16()
		bits := prefix.Bits()
		if start.Is4() {
			bits += 96
		}
		for bit := bits; bit < 128; bit++ {
			end[bit/8] |= 1 << (7 - bit%8)
		}
		endAddress := netip.AddrFrom16(end)
		if start.Is4() {
			endAddress = endAddress.Unmap()
		}
		rangeValue := interval{start, endAddress}
		if start.Is4() {
			result.v4 = append(result.v4, rangeValue)
		} else {
			result.v6 = append(result.v6, rangeValue)
		}
	}
	result.v4, result.v6 = merge(result.v4), merge(result.v6)
	return result, nil
}

func merge(ranges []interval) []interval {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start.Less(ranges[j].start) })
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || merged[len(merged)-1].end.Compare(current.start) < 0 {
			merged = append(merged, current)
		} else if current.end.Compare(merged[len(merged)-1].end) > 0 {
			merged[len(merged)-1].end = current.end
		}
	}
	return merged
}

func (n *Networks) Contains(ip netip.Addr) bool {
	if n == nil || !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	ranges := n.v6
	if ip.Is4() {
		ranges = n.v4
	}
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start.Compare(ip) > 0 }) - 1
	return i >= 0 && ranges[i].end.Compare(ip) >= 0
}
