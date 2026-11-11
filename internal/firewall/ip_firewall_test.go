package firewall

import (
	"net/netip"
	"testing"

	"http-proxy-firewall/internal/ipfirewall"
)

type providerNetworksFake struct{}

func (providerNetworksFake) Match(ip netip.Addr, selected []string) string {
	for _, id := range selected {
		if (id == "aws" || id == "gcp") && netip.MustParsePrefix("198.51.100.0/24").Contains(ip) {
			return id
		}
	}
	return ""
}
func (providerNetworksFake) IsCloudflareWorker(netip.Addr, netip.Addr, bool) bool {
	return false
}
func (providerNetworksFake) Status() ipfirewall.Status { return ipfirewall.Status{} }

func TestIPFirewallWhitelistPriorityAndEarlyBlocking(t *testing.T) {
	for _, tc := range []struct {
		name, ip             string
		custom, providers    []string
		whitelist, countries []string
		google, blocked      bool
	}{
		{name: "manual IP", ip: "198.51.100.9", custom: []string{"198.51.100.9"}, blocked: true},
		{name: "manual IPv6 subnet", ip: "2001:db8::9", custom: []string{"2001:db8::/32"}, blocked: true},
		{name: "selected provider", ip: "198.51.100.9", providers: []string{"aws"}, blocked: true},
		{name: "unselected provider", ip: "198.51.100.9"},
		{name: "whitelist IP wins", ip: "198.51.100.9", custom: []string{"198.51.100.0/24"}, providers: []string{"aws"}, whitelist: []string{"198.51.100.9"}},
		{name: "whitelist country wins", ip: "198.51.100.9", custom: []string{"198.51.100.0/24"}, countries: []string{"Turkey"}},
		{name: "loopback wins", ip: "127.0.0.1", custom: []string{"0.0.0.0/0"}},
		{name: "Googlebot cannot bypass custom blacklist", ip: "198.51.100.9", custom: []string{"198.51.100.9"}, google: true, blocked: true},
		{name: "GCP excludes verified Googlebot", ip: "198.51.100.9", providers: []string{"gcp"}, google: true},
		{name: "GCP blocks other clients", ip: "198.51.100.9", providers: []string{"gcp"}, blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Firewall.IPFirewallNetworks, cfg.Firewall.IPFirewallProviders = tc.custom, tc.providers
			cfg.Firewall.WhitelistIPs, cfg.Firewall.AllowedCountries = tc.whitelist, tc.countries
			cfg.Firewall.WhitelistCheckpoint, cfg.Firewall.CountryCheckpoint = true, true
			engine := testEngine(t, cfg, fakeIntelligence{country: "Turkey", google: tc.google})
			engine.SetIPFirewall(providerNetworksFake{})
			ctx, err := rawContext(rawRequest("GET", "/style.css", "", nil, false, "Cookie: arbitrary=accepted\r\n"), 1024, tc.ip)
			if err != nil {
				t.Fatal(err)
			}
			app := testApp(engine, nil)
			c := app.AcquireCtx(ctx)
			defer app.ReleaseCtx(c)
			decision := engine.ipDecision(c)
			if decision.blocked != tc.blocked {
				t.Fatalf("blocked=%v want=%v", decision.blocked, tc.blocked)
			}
			if len(tc.whitelist)+len(tc.countries) > 0 && (!decision.matched || decision.bypass) {
				t.Fatal("whitelist priority disabled the enabled cookie checkpoint")
			}
		})
	}
}
