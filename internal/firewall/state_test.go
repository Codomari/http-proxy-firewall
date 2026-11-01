package firewall

import (
	"testing"
	"time"
)

func TestCanonicalHostnameKeepsWWWWhileFirewallGroupsIt(t *testing.T) {
	canonical, err := CanonicalHostname("WWW.Example.TEST.:443")
	if err != nil || canonical != "www.example.test" {
		t.Fatalf("canonical host=%q error=%v", canonical, err)
	}
	normalized, err := normalizeHostname("WWW.Example.TEST.:443")
	if err != nil || normalized != "example.test" {
		t.Fatalf("firewall host=%q error=%v", normalized, err)
	}
}

func TestDDoSStateReadsWithoutIncrementingOrCreatingCounter(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.RequestThreshold = 1
	cfg.Firewall.SamplingWindow = time.Second
	e := testEngine(t, cfg, nil)
	now := time.Unix(1700000000, 0)
	e.now = func() time.Time { return now }
	if active, until := e.DDoSState("missing.example"); active || !until.IsZero() {
		t.Fatal("missing host reported penalty")
	}
	if _, ok := e.detector.hosts.Get("missing.example", now); ok {
		t.Fatal("admin read created detector entry")
	}
	if e.detector.penalized("example.test", now) {
		t.Fatal("first request penalized")
	}
	for i := 0; i < 10; i++ {
		if active, _ := e.DDoSState("www.example.test:443"); active {
			t.Fatal("admin reads triggered threshold")
		}
	}
	state, _ := e.detector.hosts.Get("example.test", now)
	if state.count != 1 {
		t.Fatal("admin reads incremented counter")
	}
	if !e.detector.penalized("example.test", now) {
		t.Fatal("threshold did not trigger")
	}
	if active, until := e.DDoSState("WWW.Example.TEST."); !active || !until.Equal(now.Add(cfg.Firewall.PenaltyLifetime)) {
		t.Fatalf("penalty not exposed: active=%t until=%v", active, until)
	}
	now = now.Add(cfg.Firewall.PenaltyLifetime)
	if active, until := e.DDoSState("example.test"); active || !until.IsZero() {
		t.Fatal("expired penalty remained active")
	}
}
