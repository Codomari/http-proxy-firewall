package firewall

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"

	"github.com/gofiber/fiber/v3"
)

func TestWhitelistCheckpointSwitchesAndRulePriority(t *testing.T) {
	for _, tc := range []struct {
		name                                                           string
		ipMatch, countryMatch, ipCheckpoint, countryCheckpoint, bypass bool
	}{
		{"IP checkpoint enabled", true, false, true, false, false},
		{"IP checkpoint disabled", true, false, false, true, true},
		{"country checkpoint enabled", false, true, false, true, false},
		{"country checkpoint disabled", false, true, true, false, true},
		{"IP enabled wins overlap", true, true, true, false, false},
		{"country enabled wins overlap", true, true, false, true, false},
		{"both bypass", true, true, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t, testConfig(), fakeIntelligence{country: "Turkey"})
			rules := config.GeneralRules{MaxBodyBytes: testConfig().Firewall.MaxBodyBytes, GCPercent: 100, GCMemoryLimit: "off", ConnectionLimits: config.ConnectionLimitsFromConfig(config.Defaults()), IPCheckpoint: tc.ipCheckpoint, CountryCheckpoint: tc.countryCheckpoint, DDoSThreshold: 200}
			if tc.ipMatch {
				rules.WhitelistIPs = []string{"198.51.100.1"}
			}
			if tc.countryMatch {
				rules.AllowedCountries = []string{"Turkey"}
			}
			if err := e.SetGeneralRules(rules); err != nil {
				t.Fatal(err)
			}
			if got := e.bypass(context.Background(), netip.MustParseAddr("198.51.100.1")); got != tc.bypass {
				t.Fatalf("bypass=%v want=%v", got, tc.bypass)
			}
			// A real penalized request must obtain the cookie challenge when the
			// switches require it, or reach the upstream when bypass is allowed.
			for range (int(e.detector.threshold) + 1) * int(e.detector.window/time.Second) {
				e.detector.penalized("example.test", e.now())
			}
			forwarded := false
			app := testApp(e, func(c fiber.Ctx) error { forwarded = true; return c.SendStatus(204) })
			ctx := serve(t, app, e, rawRequest("GET", "/", "", nil, false, ""), "198.51.100.1")
			if forwarded != tc.bypass || !tc.bypass && len(ctx.Response.Header.Peek("Set-Cookie")) == 0 {
				t.Fatalf("checkpoint behavior wrong: forwarded=%v status=%d", forwarded, ctx.Response.StatusCode())
			}
			// Neither switch can exempt a matched client from the CVE filter.
			forwarded = false
			body := []byte("--b\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n--b--\r\n")
			ctx = serve(t, app, e, rawRequest("POST", "/", "multipart/form-data; boundary=b", body, false, ""), "198.51.100.1")
			if ctx.Response.StatusCode() != 403 || forwarded {
				t.Fatal("whitelist bypassed CVE validation")
			}
			ctx = serve(t, app, e, rawRequest("GET", "/?password=secret", "", nil, false, "User-Agent: Googlebot\r\n"), "198.51.100.1")
			if ctx.Response.StatusCode() != 403 || forwarded {
				t.Fatal("whitelist bypassed bot-query rule")
			}
		})
	}
}

func TestGeneralRulesPublishAtomicallyDuringRequests(t *testing.T) {
	e := testEngine(t, testConfig(), fakeIntelligence{country: "Turkey"})
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for i := range 100 {
				if worker == 0 {
					if err := e.SetGeneralRules(config.GeneralRules{MaxBodyBytes: testConfig().Firewall.MaxBodyBytes, GCPercent: 100, GCMemoryLimit: "off", ConnectionLimits: config.ConnectionLimitsFromConfig(config.Defaults()), WhitelistIPs: []string{"198.51.100.1"}, IPCheckpoint: i%2 == 0, DDoSThreshold: uint64(i + 1)}); err != nil {
						t.Error(err)
					}
				} else {
					e.bypass(context.Background(), netip.MustParseAddr("198.51.100.1"))
					e.detector.penalized("example.test", e.now())
				}
			}
		})
	}
	wg.Wait()
}

func TestDDoSThresholdUpdatesWithoutResettingActivePenalty(t *testing.T) {
	e := testEngine(t, testConfig(), nil)
	settings := config.GeneralRules{MaxBodyBytes: testConfig().Firewall.MaxBodyBytes, GCPercent: 100, GCMemoryLimit: "off", ConnectionLimits: config.ConnectionLimitsFromConfig(config.Defaults()), DDoSThreshold: 1, IPCheckpoint: true, CountryCheckpoint: true}
	if err := e.SetGeneralRules(settings); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		e.detector.penalized("penalized.test", e.now())
	}
	if active, _ := e.DDoSState("penalized.test"); !active {
		t.Fatal("lower threshold did not activate detection")
	}
	settings.DDoSThreshold = 100
	if err := e.SetGeneralRules(settings); err != nil {
		t.Fatal(err)
	}
	if active, _ := e.DDoSState("penalized.test"); !active {
		t.Fatal("threshold edit cleared an existing penalty")
	}
	for range 20 {
		if e.detector.penalized("new.test", e.now()) {
			t.Fatal("new requests did not use the raised threshold")
		}
	}
}
