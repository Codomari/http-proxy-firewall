package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestCloudflareHostnameTrustAndSpoofProtection(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.CloudflareHostsFile = filepath.Join(t.TempDir(), "hosts.json")
	cfg.Firewall.TrustedProxies = []string{"10.0.0.0/8"}
	e := testEngine(t, cfg, nil)
	for name, enabled := range map[string]bool{"example.test": true, "*.example.test": true, "off.example.test": false, "*.off.example.test": false} {
		if err := e.SetCloudflareHost(name, enabled); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, peer, host, headers, want string }{
		{"edge IPv4", "173.245.48.1", "EXAMPLE.TEST.:443", "CF-Connecting-IP: 203.0.113.8\r\n", "203.0.113.8"},
		{"edge IPv6", "2606:4700::1", "a.b.example.test", "CF-Connecting-IP: 2001:db8::8\r\n", "2001:db8::8"},
		{"trusted intermediary", "10.0.0.2", "example.test", "CF-Connecting-IP: 203.0.113.8\r\n", "203.0.113.8"},
		{"direct spoof", "198.51.100.1", "example.test", "CF-Connecting-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1\r\n", "198.51.100.1"},
		{"other host", "173.245.48.1", "other.test", "CF-Connecting-IP: 203.0.113.8\r\n", "173.245.48.1"},
		{"exact off overrides wildcard", "173.245.48.1", "off.example.test", "CF-Connecting-IP: 203.0.113.8\r\n", "173.245.48.1"},
		{"specific wildcard off", "173.245.48.1", "a.off.example.test", "CF-Connecting-IP: 203.0.113.8\r\n", "173.245.48.1"},
		{"missing header", "173.245.48.1", "example.test", "X-Forwarded-For: 127.0.0.1\r\n", "173.245.48.1"},
		{"invalid header", "173.245.48.1", "example.test", "CF-Connecting-IP: invalid\r\n", "173.245.48.1"},
		{"duplicate header", "173.245.48.1", "example.test", "CF-Connecting-IP: 203.0.113.8\r\nCF-Connecting-IP: 127.0.0.1\r\n", "173.245.48.1"},
		{"zoned address", "173.245.48.1", "example.test", "CF-Connecting-IP: fe80::1%eth0\r\n", "173.245.48.1"},
		{"pseudo IPv4", "173.245.48.1", "example.test", "CF-Connecting-IP: 240.1.2.3\r\nCF-Connecting-IPv6: 2001:db8::8\r\n", "2001:db8::8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed, early := "", ""
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error { early = e.ResolveClientIP(c); return c.Next() })
			app.Use(e.Handler)
			app.Use(func(c fiber.Ctx) error { observed = ClientIP(c); return c.SendStatus(200) })
			raw := strings.Replace(rawRequest("GET", "/", "", nil, false, tc.headers), "Host: example.test", "Host: "+tc.host, 1)
			serve(t, app, e, raw, tc.peer)
			if observed != tc.want || early != tc.want {
				t.Fatalf("client=%q early=%q want=%q", observed, early, tc.want)
			}
		})
	}
}

func TestCloudflareSettingsPersistenceAndFailedSave(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.CloudflareHostsFile = filepath.Join(t.TempDir(), "nested", "hosts.json")
	e := testEngine(t, cfg, nil)
	if err := e.SetCloudflareHost("*.Example.TEST.", true); err != nil {
		t.Fatal(err)
	}
	if err := e.SetCloudflareHost("off.example.test", false); err != nil {
		t.Fatal(err)
	}
	restarted := testEngine(t, cfg, nil)
	if enabled, configured := restarted.cloudflare.match("www.example.test:443"); !enabled || !configured {
		t.Fatal("enabled wildcard not restored")
	}
	if enabled, configured := restarted.cloudflare.match("off.example.test"); enabled || !configured {
		t.Fatal("disabled override not restored")
	}
	if info, err := os.Stat(cfg.Firewall.CloudflareHostsFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("hostname settings not private")
	}
	if err := e.SetCloudflareHost("../../unsafe", true); err == nil {
		t.Fatal("invalid host setting accepted")
	}
	// Renaming over a directory fails, retaining the last published rules.
	blocked := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	e.cloudflare.path = blocked
	if err := e.SetCloudflareHost("new.example.test", true); err == nil {
		t.Fatal("failed persistence was reported successful")
	}
	if enabled, _ := e.cloudflare.match("off.example.test"); enabled {
		t.Fatal("failed save changed rules")
	}
	if len(e.CloudflareHosts()) != 2 {
		t.Fatal("failed save published a new hostname")
	}
}

func TestCloudflarePlainDomainIncludesWWW(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.CloudflareHostsFile = filepath.Join(t.TempDir(), "hosts.json")
	e := testEngine(t, cfg, nil)
	if err := e.SetCloudflareHost("Example.TEST.", true); err != nil {
		t.Fatal(err)
	}
	// Reload the saved rule to verify this default also applies after restart,
	// without storing a second, potentially conflicting www rule.
	e = testEngine(t, cfg, nil)
	for _, host := range []string{"example.test", "www.example.test", "WWW.Example.TEST.:443"} {
		if enabled, configured := e.cloudflare.match(host); !enabled || !configured {
			t.Fatalf("plain rule did not cover %q", host)
		}
	}
	for _, host := range []string{"api.example.test", "www.api.example.test", "www.www.example.test", "example.test.evil"} {
		if _, configured := e.cloudflare.match(host); configured {
			t.Fatalf("plain rule unexpectedly covered %q", host)
		}
	}
	if len(e.CloudflareHosts()) != 1 {
		t.Fatal("implicit www alias added a separate rule")
	}
	if err := e.SetCloudflareHost("www.example.test", false); err != nil {
		t.Fatal(err)
	}
	if enabled, configured := e.cloudflare.match("www.example.test"); enabled || !configured {
		t.Fatal("explicit www rule did not override the base domain")
	}
	if enabled, _ := e.cloudflare.match("example.test"); !enabled {
		t.Fatal("www override altered the base domain")
	}
	if err := e.SetCloudflareHost("example.test", false); err != nil {
		t.Fatal(err)
	}
	if enabled, configured := e.cloudflare.match("www.example.test"); enabled || !configured {
		t.Fatal("disabled domain rule still enabled www")
	}
}

func TestCloudflareConcurrentUpdatesAndResolution(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.CloudflareHostsFile = filepath.Join(t.TempDir(), "hosts.json")
	e := testEngine(t, cfg, nil)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if err := e.SetCloudflareHost("example.test", true); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			e.cloudflare.match("example.test")
			e.CloudflareHosts()
		})
	}
	wg.Wait()
}
