package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"

	"github.com/gofiber/fiber/v3"
)

type testGeneralRulesSource struct {
	settings config.GeneralRules
	saves    int
}

func (source *testGeneralRulesSource) DDoSState(string) (bool, time.Time) { return false, time.Time{} }
func (source *testGeneralRulesSource) SetGeneralRules(settings config.GeneralRules) error {
	source.settings = settings
	source.saves++
	return nil
}

func TestGeneralRulesAPIAuthenticationValidationPersistenceAndRuntime(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.OverrideYAML)
	const original = "# private settings\nenv:\n  - key: REDIS_PASSWORD\n    value: private-value-never-returned\n  - key: IP_FILTER_WHITELIST\n    value: 198.51.100.1\n  - key: IP_FILTER_ALLOWED_COUNTRIES\n    value: Turkey\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Admin.Enabled, cfg.Admin.URI = true, "ops"
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	source := &testGeneralRulesSource{}
	h, err := New(cfg, monitoring.New(cfg), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.generalFile.Path = path
	app := fiber.New(fiber.Config{StreamRequestBody: true})
	h.Mount(app)
	settings := config.GeneralRules{WhitelistIPs: []string{"203.0.113.8"}, WhitelistNetworks: []string{"203.0.113.8/24"}, AllowedCountries: []string{"Azerbaijan", "Turkey"}, IPCheckpoint: true, CountryCheckpoint: false, DDoSThreshold: 350}
	payload, _ := json.Marshal(settings)
	call := func(method, body, site, media string, auth, csrf bool) (int, []byte) {
		t.Helper()
		req := httptest.NewRequest(method, "http://admin.example/ops/api/general-rules", strings.NewReader(body))
		if auth {
			req.Header.Set("Authorization", validBasic())
		}
		if csrf {
			req.Header.Set("X-PF-Admin", "1")
		}
		if media != "" {
			req.Header.Set("Content-Type", media)
		}
		req.Header.Set("Sec-Fetch-Site", site)
		response, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		if strings.Contains(string(data), "private-value") {
			t.Fatal("API exposed an unrelated YAML secret")
		}
		return response.StatusCode, data
	}
	for _, tc := range []struct {
		method, body, site, media string
		auth, csrf                bool
		want                      int
	}{
		{"GET", "", "", "", false, false, 401},
		{"POST", string(payload), "", "application/json", false, true, 401},
		{"POST", string(payload), "", "application/json", true, false, 403},
		{"POST", string(payload), "cross-site", "application/json", true, true, 403},
		{"POST", string(payload), "", "text/plain", true, true, 415},
		{"POST", `{}`, "", "application/json", true, true, 400},
		{"POST", string(payload) + "{}", "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"ddos_threshold":350`, `"ddos_threshold":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"ddos_threshold":350`, `"ddos_threshold":1.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), "203.0.113.8", "bad-ip", 1), "", "application/json", true, true, 400},
		{"POST", strings.Repeat("x", 65537), "", "application/json", true, true, 413},
		{"DELETE", "", "", "", true, true, 405},
	} {
		status, _ := call(tc.method, tc.body, tc.site, tc.media, tc.auth, tc.csrf)
		if status != tc.want {
			t.Fatalf("%s status=%d want=%d", tc.method, status, tc.want)
		}
	}
	if source.saves != 0 {
		t.Fatal("invalid request changed active rules")
	}
	before, _ := os.ReadFile(path)
	if string(before) != original {
		t.Fatal("invalid request changed override YAML")
	}
	status, data := call("GET", "", "", "", true, false)
	var loaded generalRulesSnapshot
	if status != 200 || json.Unmarshal(data, &loaded) != nil || len(loaded.WhitelistIPs) != 1 || loaded.WhitelistIPs[0] != "198.51.100.1" || !loaded.IPCheckpoint {
		t.Fatal("GET did not read YAML")
	}
	status, data = call("POST", string(payload), "same-origin", "application/json", true, true)
	if status != 200 || json.Unmarshal(data, &loaded) != nil {
		t.Fatalf("save failed: %d %s", status, data)
	}
	want, _ := settings.Normalize()
	if source.saves != 1 || !reflect.DeepEqual(source.settings, want) || !reflect.DeepEqual(loaded.GeneralRules, want) {
		t.Fatal("saved settings were not applied immediately")
	}
	file := config.GeneralRulesFile{Path: path}
	persisted, err := file.Read()
	if err != nil || !reflect.DeepEqual(persisted, want) {
		t.Fatal("YAML save did not persist settings")
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	status, _ = call("POST", string(payload), "", "application/json", true, true)
	if status != http.StatusServiceUnavailable || source.saves != 1 {
		t.Fatal("file failure changed active settings")
	}
	h.enabled = false
	status, _ = call("GET", "", "", "", true, false)
	if status != 404 {
		t.Fatal("disabled admin exposed general rules")
	}
}
