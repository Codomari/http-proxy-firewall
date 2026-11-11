package config

import (
	"errors"
	"io"
	"math"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
)

type Runtime struct {
	GCPercent        int
	MemoryLimitBytes int64
}

func gcPercentValue(percent int) string {
	if percent == -1 {
		return "off"
	}
	return strconv.Itoa(percent)
}

// Apply also handles YAML values, which are exported after Go initializes.
func (settings Runtime) Apply() {
	debug.SetGCPercent(settings.GCPercent)
	debug.SetMemoryLimit(settings.MemoryLimitBytes)
}

func RuntimeFromValues(values map[string]string) (Runtime, error) {
	settings := Runtime{GCPercent: 100, MemoryLimitBytes: math.MaxInt64}
	if value := values["GOGC"]; value != "" {
		if value == "off" {
			settings.GCPercent = -1
		} else {
			percent, err := strconv.Atoi(value)
			if err != nil || percent < 0 {
				return Runtime{}, errors.New("GOGC must be a non-negative integer or off")
			}
			settings.GCPercent = percent
		}
	}
	if value := values["GOMEMLIMIT"]; value != "" && value != "off" {
		multiplier := int64(1)
		for _, unit := range []struct {
			suffix string
			bytes  int64
		}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40}, {"B", 1}} {
			if strings.HasSuffix(value, unit.suffix) {
				value = strings.TrimSuffix(value, unit.suffix)
				multiplier = unit.bytes
				break
			}
		}
		count, err := strconv.ParseInt(value, 10, 64)
		if err != nil || count <= 0 || count > math.MaxInt64/multiplier {
			return Runtime{}, errors.New("GOMEMLIMIT must be a positive integer in bytes, B, KiB, MiB, GiB or TiB, or off")
		}
		settings.MemoryLimitBytes = count * multiplier
	}
	return settings, nil
}

// Reload preserves the original environment and flags, excluding values the
// application exported from YAML after startup.
func (c Config) Reload() (Config, error) {
	if c.Source == nil {
		return Config{}, errors.New("configuration reload requires a YAML source")
	}
	document, err := c.Source.Read()
	if err != nil {
		return Config{}, err
	}
	values := make(map[string]string)
	if err := mergeDeploymentValues(values, document.Environment()); err != nil {
		return Config{}, err
	}
	if err := mergeDeploymentValues(values, c.processEnvironment); err != nil {
		return Config{}, err
	}
	return Parse(c.arguments, values, io.Discard)
}

// RestartChanges reports startup settings; controls applied live are excluded.
func (c Config) RestartChanges(next Config) []string {
	var changes []string
	add := func(name string, left, right any) {
		if !reflect.DeepEqual(left, right) {
			changes = append(changes, name)
		}
	}
	add("Garbage collection", c.Runtime, next.Runtime)
	c.HTTP.MaxConcurrentRequests, next.HTTP.MaxConcurrentRequests = 0, 0
	add("HTTP listeners and timeouts", c.HTTP, next.HTTP)
	for _, proxy := range []*Proxy{&c.Proxy, &next.Proxy} {
		proxy.MaxConnections, proxy.MaxOverflowConnections, proxy.RequestRetryTimes = 0, 0, 0
		proxy.AllowOverflow = false
	}
	add("Upstream configuration", c.Proxy, next.Proxy)
	for _, firewall := range []*Firewall{&c.Firewall, &next.Firewall} {
		firewall.MaxBodyBytes, firewall.RequestThreshold = 0, 0
		firewall.WhitelistIPs, firewall.WhitelistNetworks, firewall.AllowedCountries = nil, nil, nil
		firewall.IPFirewallProviders, firewall.IPFirewallNetworks = nil, nil
		firewall.WhitelistCheckpoint, firewall.CountryCheckpoint = false, false
	}
	add("Firewall startup settings", c.Firewall, next.Firewall)
	add("TLS configuration", c.TLS, next.TLS)
	add("Redis configuration", c.Redis, next.Redis)
	add("IP intelligence", c.Intelligence, next.Intelligence)
	add("Monitoring configuration", c.Observability, next.Observability)
	add("Admin configuration", c.Admin, next.Admin)
	return changes
}
