package firewall

import (
	"context"
	"net/netip"
	"strings"

	"http-proxy-firewall/internal/config"
)

type generalRules struct {
	settings  config.GeneralRules
	whitelist []netip.Prefix
	countries map[string]struct{}
}

func compileGeneralRules(settings config.GeneralRules) (*generalRules, error) {
	settings, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	values := append([]string{"127.0.0.0/8", "::1/128"}, settings.WhitelistNetworks...)
	values = append(values, settings.WhitelistIPs...)
	whitelist, err := parseNetworks(values)
	if err != nil {
		return nil, err
	}
	countries := make(map[string]struct{}, len(settings.AllowedCountries))
	for _, country := range settings.AllowedCountries {
		countries[strings.ToLower(country)] = struct{}{}
	}
	return &generalRules{settings: settings, whitelist: whitelist, countries: countries}, nil
}

// SetGeneralRules publishes one immutable snapshot so requests never observe a
// mix of old whitelist entries and new checkpoint switches.
func (e *Engine) SetGeneralRules(settings config.GeneralRules) error {
	rules, err := compileGeneralRules(settings)
	if err != nil {
		return err
	}
	e.detector.mu.Lock()
	e.detector.threshold = rules.settings.DDoSThreshold
	e.general.Store(rules)
	e.detector.mu.Unlock()
	return nil
}

func (e *Engine) whitelistBypass(ctx context.Context, address netip.Addr) (matched, bypass bool) {
	rules := e.general.Load()
	if rules == nil {
		return false, false
	}
	ip := containsAddress(rules.whitelist, address)
	country := false
	if e.intelligence != nil && len(rules.countries) > 0 {
		_, country = rules.countries[strings.ToLower(strings.TrimSpace(e.intelligence.Country(ctx, address)))]
	}
	if ip && rules.settings.IPCheckpoint || country && rules.settings.CountryCheckpoint {
		return true, false
	}
	return ip || country, ip || country
}
