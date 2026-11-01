package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"
)

const (
	maxGoogleBytes    = 4 << 20
	maxGooglePrefixes = 16384
)

type ipInterval struct {
	start netip.Addr
	end   netip.Addr
}

// Published snapshots are immutable. Merged, sorted intervals make lookups
// logarithmic instead of scanning every prefix on every request.
type googleSnapshot struct {
	records []string
	v4      []ipInterval
	v6      []ipInterval
}

func (s *Service) IsGoogleBot(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	snapshot := s.google.Load()
	if snapshot == nil {
		return false
	}
	ranges := snapshot.v6
	if ip.Is4() {
		ranges = snapshot.v4
	}
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start.Compare(ip) > 0 }) - 1
	return i >= 0 && ranges[i].end.Compare(ip) >= 0
}

func (s *Service) runGoogle(ctx context.Context) {
	if s.remote != nil {
		data, ok, err := s.remote.Get(ctx, googleStorageKey)
		if err == nil && ok && len(data) <= maxGoogleBytes {
			if snapshot, err := parseGoogleRecords(strings.Split(string(data), ",")); err == nil {
				s.google.Store(snapshot)
			}
		}
	}
	if s.cfg.Intelligence.GoogleRangesURL != "" {
		s.runRefresh(ctx, "Google ranges", s.refreshGoogle)
	}
}

func (s *Service) refreshGoogle(ctx context.Context) error {
	resp, err := s.request(ctx, s.cfg.Intelligence.GoogleRangesURL, maxGoogleBytes)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGoogleBytes+1))
	if err != nil {
		return errors.New("cannot read Google ranges")
	}
	if len(data) > maxGoogleBytes {
		return errors.New("Google ranges exceed size limit")
	}
	var response struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Prefixes) > maxGooglePrefixes {
		return errors.New("invalid Google ranges response")
	}
	records := make([]string, 0, len(response.Prefixes))
	for _, prefix := range response.Prefixes {
		if (prefix.IPv4 == "") == (prefix.IPv6 == "") {
			return errors.New("invalid Google prefix entry")
		}
		if prefix.IPv4 != "" {
			parsed, err := netip.ParsePrefix(prefix.IPv4)
			if err != nil || !parsed.Addr().Is4() {
				return errors.New("invalid Google IPv4 prefix")
			}
			records = append(records, prefix.IPv4)
		} else {
			parsed, err := netip.ParsePrefix(prefix.IPv6)
			if err != nil || !parsed.Addr().Is6() || parsed.Addr().Is4In6() {
				return errors.New("invalid Google IPv6 prefix")
			}
			records = append(records, prefix.IPv6)
		}
	}
	snapshot, err := parseGoogleRecords(records)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.google.Store(snapshot)
	if s.remote != nil {
		s.remote.Set(googleStorageKey, []byte(strings.Join(snapshot.records, ", ")), s.cfg.Intelligence.RefreshInterval)
	}
	return nil
}

func parseGoogleRecords(records []string) (*googleSnapshot, error) {
	if len(records) == 0 || len(records) > maxGooglePrefixes {
		return nil, errors.New("invalid Google prefix count")
	}
	snapshot := &googleSnapshot{records: make([]string, 0, len(records))}
	seen := make(map[netip.Prefix]struct{}, len(records))
	for _, raw := range records {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, errors.New("invalid Google CIDR")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, errors.New("invalid mapped Google CIDR")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		snapshot.records = append(snapshot.records, prefix.String())
		rangeValue := intervalForPrefix(prefix)
		if prefix.Addr().Is4() {
			snapshot.v4 = append(snapshot.v4, rangeValue)
		} else {
			snapshot.v6 = append(snapshot.v6, rangeValue)
		}
	}
	snapshot.v4 = mergeIntervals(snapshot.v4)
	snapshot.v6 = mergeIntervals(snapshot.v6)
	return snapshot, nil
}

func intervalForPrefix(prefix netip.Prefix) ipInterval {
	start := prefix.Masked().Addr()
	if start.Is4() {
		end := start.As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			end[bit/8] |= 1 << (7 - bit%8)
		}
		return ipInterval{start: start, end: netip.AddrFrom4(end)}
	}
	end := start.As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		end[bit/8] |= 1 << (7 - bit%8)
	}
	return ipInterval{start: start, end: netip.AddrFrom16(end)}
}

func mergeIntervals(ranges []ipInterval) []ipInterval {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start.Compare(ranges[j].start) < 0 })
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || merged[len(merged)-1].end.Compare(current.start) < 0 {
			merged = append(merged, current)
			continue
		}
		if current.end.Compare(merged[len(merged)-1].end) > 0 {
			merged[len(merged)-1].end = current.end
		}
	}
	return merged
}
