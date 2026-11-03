package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"http-proxy-firewall/internal/config"

	"github.com/gofiber/fiber/v3"
)

const maxCloudflareHosts = 256

var cloudflarePseudoIPv4 = netip.MustParsePrefix("240.0.0.0/4")

// Published ranges verified 2026-11-03. Keep in sync with the authoritative lists:
// https://www.cloudflare.com/ips-v4/ and https://www.cloudflare.com/ips-v6/
var cloudflareNetworks = func() []netip.Prefix {
	var result []netip.Prefix
	for _, cidr := range strings.Fields(`
173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`) {
		result = append(result, netip.MustParsePrefix(cidr))
	}
	return result
}()

type CloudflareHost struct {
	Hostname string `json:"hostname"`
	Enabled  bool   `json:"enabled"`
}

type cloudflareRules struct{ hosts map[string]bool }

type cloudflareSettings struct {
	mu    sync.Mutex
	path  string
	rules atomic.Pointer[cloudflareRules]
	store *config.YAMLStore
}

// CanonicalHostnamePattern validates DNS host patterns without accepting ports,
// URL paths or IP header syntax. Retained strings own their storage.
func CanonicalHostnamePattern(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	base := strings.TrimPrefix(name, "*.")
	if len(base) == 0 || len(base) > 253 {
		return "", errors.New("enter a hostname or wildcard such as *.example.com")
	}
	for _, label := range strings.Split(base, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("use letters, numbers, dashes and dots; only a leading *. wildcard is allowed")
			}
		}
	}
	return strings.Clone(name), nil
}

func HostnameMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return len(host) > len(pattern)-1 && strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
}

func (s *cloudflareSettings) load(path string) error {
	s.path = path
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	if err != nil {
		return err
	}
	if len(data) > 128<<10 {
		return errors.New("Cloudflare hostname settings exceed 128 KiB")
	}
	var rules map[string]bool
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	if len(rules) > maxCloudflareHosts {
		return errors.New("Cloudflare settings exceed 256 hostname rules")
	}
	normalized := make(map[string]bool, len(rules))
	for raw, enabled := range rules {
		name, err := CanonicalHostnamePattern(raw)
		if err != nil {
			return err
		}
		if _, exists := normalized[name]; exists {
			return errors.New("duplicate normalized Cloudflare hostname rule")
		}
		normalized[name] = enabled
	}
	s.rules.Store(&cloudflareRules{hosts: normalized})
	return nil
}

func (e *Engine) CloudflareHosts() []CloudflareHost {
	result := []CloudflareHost{}
	if rules := e.cloudflare.rules.Load(); rules != nil {
		for name, enabled := range rules.hosts {
			result = append(result, CloudflareHost{Hostname: name, Enabled: enabled})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Hostname < result[j].Hostname })
	return result
}

func (s *cloudflareSettings) loadYAML(store *config.YAMLStore) error {
	document, err := store.Read()
	if err != nil {
		return err
	}
	hosts := make(map[string]bool)
	for _, rule := range document.Rules {
		for _, param := range rule.Params {
			host, err := CanonicalHostnamePattern(param.Key)
			if err != nil {
				return err
			}
			hosts[host] = true
		}
	}
	if len(hosts) > maxCloudflareHosts {
		return errors.New("Cloudflare settings exceed 256 hostname rules")
	}
	s.store = store
	s.rules.Store(&cloudflareRules{hosts: hosts})
	return nil
}

// SetCloudflareHost persists first, then atomically publishes immutable rules so
// a failed save cannot silently change request identity or source-IP filtering.
func (e *Engine) SetCloudflareHost(raw string, enabled bool) error {
	name, err := CanonicalHostnamePattern(raw)
	if err != nil {
		return err
	}
	s := &e.cloudflare
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		if enabled {
			if current := s.rules.Load(); current != nil && !current.hosts[name] && len(current.hosts) >= maxCloudflareHosts {
				return errors.New("Cloudflare settings exceed 256 hostname rules")
			}
		}
		if err := s.store.SetCloudflareHost(name, enabled); err != nil {
			return err
		}
		return s.loadYAML(s.store)
	}
	if s.path == "" {
		return errors.New("Cloudflare hostname settings file is not configured")
	}
	next := make(map[string]bool)
	if current := s.rules.Load(); current != nil {
		for name, value := range current.hosts {
			next[name] = value
		}
	}
	next[name] = enabled
	if len(next) > maxCloudflareHosts {
		return errors.New("Cloudflare settings exceed 256 hostname rules")
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".cloudflare-hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	err = errors.Join(writeErr, syncErr, file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), s.path); err != nil {
		return err
	}
	s.rules.Store(&cloudflareRules{hosts: next})
	return nil
}

func (s *cloudflareSettings) match(raw string) (enabled, configured bool) {
	rules := s.rules.Load()
	if rules == nil || len(rules.hosts) == 0 {
		return false, false
	}
	host, err := CanonicalHostname(raw)
	if err != nil {
		return false, false
	}
	if value, exists := rules.hosts[host]; exists {
		return value, true
	}
	// Plain domain rules include their conventional www alias. A rule for the
	// requested hostname itself takes precedence over this inherited setting.
	if bare, ok := strings.CutPrefix(host, "www."); ok {
		if value, exists := rules.hosts[bare]; exists {
			return value, true
		}
	}
	best := 0
	for pattern, value := range rules.hosts {
		if strings.HasPrefix(pattern, "*.") && len(pattern) > best && HostnameMatches(pattern, host) {
			best, enabled, configured = len(pattern), value, true
		}
	}
	return enabled, configured
}

func cloudflareClient(c fiber.Ctx) (netip.Addr, bool) {
	values := c.Request().Header.PeekAll("CF-Connecting-IP")
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(values[0])))
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	// Pseudo IPv4 overwrite mode keeps the actual IPv6 address in this header.
	if cloudflarePseudoIPv4.Contains(address) {
		values = c.Request().Header.PeekAll("CF-Connecting-IPv6")
		if len(values) == 1 {
			ipv6, err := netip.ParseAddr(strings.TrimSpace(string(values[0])))
			if err == nil && ipv6.Is6() && !ipv6.Is4In6() && ipv6.Zone() == "" {
				return ipv6, true
			}
		}
	}
	return address, true
}
