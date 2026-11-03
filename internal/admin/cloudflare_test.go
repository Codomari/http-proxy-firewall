package admin

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/monitoring"
)

func TestCloudflareAdminSettingsAuthenticationCSRFAndPersistence(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled, cfg.Admin.URI = true, "ops"
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	cfg.Firewall.CloudflareHostsFile = filepath.Join(t.TempDir(), "hosts.json")
	engine, err := firewall.New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, monitoring.New(cfg), engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	h.Mount(app)
	for _, tc := range []struct {
		method, query, site string
		auth, csrf          bool
		want                int
	}{
		{"GET", "", "", false, false, 401},
		{"POST", "hostname=example.com&enabled=true", "", false, true, 401},
		{"POST", "hostname=example.com&enabled=true", "", true, false, 403},
		{"POST", "hostname=example.com&enabled=true", "cross-site", true, true, 403},
		{"POST", "hostname=../../unsafe&enabled=true", "", true, true, 400},
		{"POST", "hostname=example.com&enabled=maybe", "", true, true, 400},
		{"POST", "hostname=example.com&enabled=true", "same-origin", true, true, 200},
		{"POST", "hostname=example.com&enabled=false", "same-origin", true, true, 200},
		{"DELETE", "", "", true, true, 405},
	} {
		req := httptest.NewRequest(tc.method, "http://admin.example/ops/api/cloudflare-hosts?"+tc.query, nil)
		if tc.auth {
			req.Header.Set("Authorization", validBasic())
		}
		if tc.csrf {
			req.Header.Set("X-PF-Admin", "1")
		}
		req.Header.Set("Sec-Fetch-Site", tc.site)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s %s: status=%d want=%d", tc.method, tc.query, resp.StatusCode, tc.want)
		}
	}
	restarted, err := firewall.New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := restarted.CloudflareHosts()
	if len(settings) != 1 || settings[0].Hostname != "example.com" || settings[0].Enabled {
		t.Fatal("hostname switch did not persist")
	}
	resp := request(t, app, "GET", "/ops/api/cloudflare-hosts", validBasic())
	var result cloudflareSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Available || len(result.Hosts) != 1 {
		t.Fatalf("settings API: %+v %v", result, err)
	}
	h.enabled = false
	if request(t, app, "GET", "/ops/api/cloudflare-hosts", validBasic()).StatusCode != 404 {
		t.Fatal("disabled admin exposes hostname settings")
	}
}
