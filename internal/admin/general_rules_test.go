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
	retries  int
	limits   config.ConnectionLimits
}

func (source *testGeneralRulesSource) DDoSState(string) (bool, time.Time) { return false, time.Time{} }
func (source *testGeneralRulesSource) SetRequestRetryTimes(times int)     { source.retries = times }
func (source *testGeneralRulesSource) SetConnectionLimits(limits config.ConnectionLimits) {
	source.limits = limits
}
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
	h.SetUpstreamSettings(source)
	h.SetConnectionSettings(source)
	app := fiber.New(fiber.Config{StreamRequestBody: true})
	h.Mount(app)
	settings := config.GeneralRules{MaxBodyBytes: cfg.Firewall.MaxBodyBytes, GCPercent: 100, GCMemoryLimit: "off", ConnectionLimits: config.ConnectionLimitsFromConfig(cfg), WhitelistIPs: []string{"203.0.113.8"}, WhitelistNetworks: []string{"203.0.113.8/24"}, AllowedCountries: []string{"Azerbaijan", "Turkey"}, IPCheckpoint: true, CountryCheckpoint: false, DDoSThreshold: 350, UpstreamRequestRetryTimes: 5}
	settings.ConnectionLimits = config.ConnectionLimits{MaxConcurrentRequests: 8, UpstreamMaxConnections: 2, UpstreamAllowOverflow: true, UpstreamMaxOverflowConnections: 4}
	settings.MaxBodyBytes, settings.MaxBufferedBytes, settings.GCPercent, settings.GCMemoryLimit = 128<<20, 512<<20, 50, "512MiB"
	settings.HTTP2Enable, settings.IdleRequestTimeout = true, "5s"
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
		{"POST", strings.Replace(string(payload), `"max_body_bytes":134217728`, `"max_body_bytes":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_body_bytes":134217728`, `"max_body_bytes":-1`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_body_bytes":134217728`, `"max_body_bytes":1.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_body_bytes":134217728`, `"max_body_bytes":268435456`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":-1`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":1.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":134217728`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":134217727`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":9007199254740992`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_buffered_bytes":536870912`, `"max_buffered_bytes":9223372036854775808`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"http2_enable":true`, `"http2_enable":"yes"`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"idle_request_timeout":"5s"`, `"idle_request_timeout":"0s"`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"idle_request_timeout":"5s"`, `"idle_request_timeout":"-1s"`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"idle_request_timeout":"5s"`, `"idle_request_timeout":""`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"idle_request_timeout":"5s"`, `"idle_request_timeout":"invalid"`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"idle_request_timeout":"5s"`, `"idle_request_timeout":15`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"gc_percent":50`, `"gc_percent":-2`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"gc_memory_limit":"512MiB"`, `"gc_memory_limit":"1.5GiB"`, 1), "", "application/json", true, true, 400},
		{"POST", string(payload) + "{}", "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"ddos_threshold":350`, `"ddos_threshold":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"ddos_threshold":350`, `"ddos_threshold":1.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_request_retry_times":5`, `"upstream_request_retry_times":-1`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_request_retry_times":5`, `"upstream_request_retry_times":1.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"max_concurrent_requests":8`, `"max_concurrent_requests":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_max_connections":2`, `"upstream_max_connections":0`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_max_connections":2`, `"upstream_max_connections":2.5`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_max_overflow_connections":4`, `"upstream_max_overflow_connections":1`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_max_overflow_connections":4`, `"upstream_max_overflow_connections":-1`, 1), "", "application/json", true, true, 400},
		{"POST", strings.Replace(string(payload), `"upstream_allow_overflow":true`, `"upstream_allow_overflow":"yes"`, 1), "", "application/json", true, true, 400},
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
	if status != 200 || json.Unmarshal(data, &loaded) != nil || len(loaded.WhitelistIPs) != 1 || loaded.WhitelistIPs[0] != "198.51.100.1" || !loaded.IPCheckpoint || loaded.UpstreamRequestRetryTimes != 3 || !loaded.UpstreamAvailable || !loaded.ConnectionLimitsAvailable || loaded.MaxConcurrentRequests != 256 || loaded.UpstreamMaxConnections != 256 || loaded.UpstreamAllowOverflow || loaded.UpstreamMaxOverflowConnections != 512 {
		t.Fatal("GET did not read YAML")
	}
	if loaded.MaxBufferedBytes != cfg.Firewall.MaxBufferedBytes || loaded.ActiveMaxBufferedBytes != cfg.Firewall.MaxBufferedBytes || loaded.MaxBufferedBytesCeiling != maxAdminByteCount {
		t.Fatal("GET did not expose the default, active and maximum buffer budgets")
	}
	status, data = call("POST", string(payload), "same-origin", "application/json", true, true)
	if status != 200 || json.Unmarshal(data, &loaded) != nil {
		t.Fatalf("save failed: %d %s", status, data)
	}
	want, _ := settings.Normalize()
	if !loaded.Restart.Required {
		t.Fatal("GC edit did not flag a restart")
	}
	if loaded.ActiveMaxBufferedBytes != cfg.Firewall.MaxBufferedBytes || loaded.MaxBodyBytesCeiling != cfg.Firewall.MaxBufferedBytes-1 {
		t.Fatal("saved buffer budget changed the active budget before restart")
	}
	if source.saves != 1 || source.retries != 5 || source.limits != settings.ConnectionLimits || !reflect.DeepEqual(source.settings, want) || !reflect.DeepEqual(loaded.GeneralRules, want) {
		t.Fatal("saved settings were not applied immediately")
	}
	file := config.GeneralRulesFile{Path: path}
	persisted, err := file.Read()
	if err != nil || !reflect.DeepEqual(persisted, want) {
		t.Fatal("YAML save did not persist settings")
	}
	// Clients predating the retry control must preserve its saved value.
	var legacy map[string]any
	json.Unmarshal(payload, &legacy)
	for _, key := range []string{"max_body_bytes", "max_buffered_bytes", "http2_enable", "idle_request_timeout", "gc_percent", "gc_memory_limit", "upstream_request_retry_times", "max_concurrent_requests", "upstream_max_connections", "upstream_allow_overflow", "upstream_max_overflow_connections"} {
		delete(legacy, key)
	}
	legacyData, _ := json.Marshal(legacy)
	legacyPayload := string(legacyData)
	status, _ = call("POST", legacyPayload, "same-origin", "application/json", true, true)
	if status != 200 || source.retries != 5 || source.limits != settings.ConnectionLimits || source.settings.MaxBodyBytes != settings.MaxBodyBytes || source.settings.MaxBufferedBytes != settings.MaxBufferedBytes || source.settings.GCMemoryLimit != settings.GCMemoryLimit || source.settings.GCPercent != settings.GCPercent {
		t.Fatal("legacy save reset newer settings")
	}
	if source.settings.HTTP2Enable != settings.HTTP2Enable || source.settings.IdleRequestTimeout != settings.IdleRequestTimeout {
		t.Fatal("legacy save reset HTTP protocol or idle timeout settings")
	}
	status, data = call("POST", strings.Replace(string(payload), `"upstream_request_retry_times":5`, `"upstream_request_retry_times":0`, 1), "same-origin", "application/json", true, true)
	persisted, err = file.Read()
	if status != 200 || source.retries != 0 || err != nil || persisted.UpstreamRequestRetryTimes != 0 {
		t.Fatalf("zero did not disable and persist retries: %d %s", status, data)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	status, _ = call("POST", string(payload), "", "application/json", true, true)
	if status != http.StatusServiceUnavailable || source.saves != 3 || source.retries != 0 {
		t.Fatal("file failure changed active settings")
	}
	h.enabled = false
	status, _ = call("GET", "", "", "", true, false)
	if status != 404 {
		t.Fatal("disabled admin exposed general rules")
	}
}

func TestGeneralRulesStartupSettingsPersistenceAndRestart(t *testing.T) {
	for _, withSource := range []bool{false, true} {
		name := "standalone override"
		if withSource {
			name = "YAML source"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, config.OverrideYAML)
			cfg := config.Defaults()
			cfg.Admin.Enabled, cfg.Admin.URI = true, "ops"
			cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
			if withSource {
				defaultPath := filepath.Join(root, config.DefaultYAML)
				if err := os.WriteFile(defaultPath, []byte("env: []\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.Source = config.NewYAMLStore(defaultPath, path)
			}
			// Parse the source just as startup does, including admin credentials.
			if withSource {
				credentials := filepath.Join(root, "admin-creds")
				if err := os.WriteFile(credentials, []byte("test-admin:test-password:with-colon\n"), 0600); err != nil {
					t.Fatal(err)
				}
				startupYAML := "env:\n  - key: PF_ADMIN_URI\n    value: ops\n  - key: PF_ADMIN_CREDS_FILE\n    value: " + credentials + "\n"
				if err := os.WriteFile(cfg.Source.DefaultPath, []byte(startupYAML), 0600); err != nil {
					t.Fatal(err)
				}
				parsed, err := cfg.Reload()
				if err != nil {
					t.Fatal(err)
				}
				parsed.Source = cfg.Source
				cfg = parsed
				if !cfg.Admin.Enabled || cfg.Admin.URI != "ops" {
					t.Fatalf("test startup did not load admin settings: enabled=%t uri=%q", cfg.Admin.Enabled, cfg.Admin.URI)
				}
			}
			source := &testGeneralRulesSource{}
			h, err := New(cfg, monitoring.New(cfg), source, nil)
			if err != nil {
				t.Fatal(err)
			}
			h.generalFile.Path = path
			h.SetUpstreamSettings(source)
			h.SetConnectionSettings(source)
			app := fiber.New(fiber.Config{StreamRequestBody: true})
			h.Mount(app)
			for _, tc := range []struct {
				name         string
				budget, body int64
				status       int
				restart      bool
				http2        bool
				idle, reason string
			}{
				{"increase budget", 512 << 20, 200 << 20, 200, true, false, "15s", "Firewall startup settings"},
				{"body exceeds active budget before restart", 512 << 20, 300 << 20, 400, false, false, "15s", ""},
				{"budget smaller than body", 128 << 20, 200 << 20, 400, false, false, "15s", ""},
				{"lower body and budget together", 128 << 20, 100 << 20, 200, true, false, "15s", "Firewall startup settings"},
				{"restore active budget", 256 << 20, 100 << 20, 200, false, false, "15s", ""},
				{"enable HTTP2", 256 << 20, 100 << 20, 200, true, true, "15s", "HTTP listeners and timeouts"},
				{"disable HTTP2 and change idle timeout", 256 << 20, 100 << 20, 200, true, false, "5s", "HTTP listeners and timeouts"},
				{"restore HTTP defaults", 256 << 20, 100 << 20, 200, false, false, "15s", ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before, _ := os.ReadFile(path)
					saves := source.saves
					settings := config.GeneralRulesFromFirewall(cfg.Firewall)
					settings.MaxBufferedBytes, settings.MaxBodyBytes = tc.budget, tc.body
					settings.HTTP2Enable, settings.IdleRequestTimeout = tc.http2, tc.idle
					payload, err := json.Marshal(settings)
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest("POST", "http://admin.example/ops/api/general-rules", strings.NewReader(string(payload)))
					req.Header.Set("Authorization", validBasic())
					req.Header.Set("X-PF-Admin", "1")
					req.Header.Set("Content-Type", "application/json")
					response, err := app.Test(req)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					data, _ := io.ReadAll(response.Body)
					if response.StatusCode != tc.status {
						t.Fatalf("status=%d want=%d: %s", response.StatusCode, tc.status, data)
					}
					if tc.status != 200 {
						after, _ := os.ReadFile(path)
						if string(after) != string(before) || source.saves != saves {
							t.Fatal("invalid buffer/body settings changed saved or active rules")
						}
						return
					}
					var result generalRulesSnapshot
					if err := json.Unmarshal(data, &result); err != nil {
						t.Fatal(err)
					}
					if result.MaxBufferedBytes != tc.budget || result.MaxBodyBytes != tc.body || result.ActiveMaxBufferedBytes != cfg.Firewall.MaxBufferedBytes || result.MaxBodyBytesCeiling != cfg.Firewall.MaxBufferedBytes-1 {
						t.Fatalf("saved and active buffer/body settings are incorrect: %+v", result)
					}
					if result.Restart.Required != tc.restart || result.Restart.Error != "" || tc.restart && !reflect.DeepEqual(result.Restart.Reasons, []string{tc.reason}) {
						t.Fatalf("incorrect startup restart state: %+v", result.Restart)
					}
					persisted, err := h.generalFile.Read()
					if err != nil || persisted.MaxBufferedBytes != tc.budget || source.settings.MaxBodyBytes != tc.body {
						t.Fatalf("buffer budget did not persist or body limit did not apply: %+v %v", persisted, err)
					}
					if persisted.HTTP2Enable != tc.http2 || persisted.IdleRequestTimeout != tc.idle || h.startup.HTTP.HTTP2Enable || h.startup.HTTP.IdleTimeout != 15*time.Second {
						t.Fatal("HTTP settings did not persist or applied before restart")
					}
					if withSource {
						next, err := cfg.Reload()
						if err != nil || next.Firewall.MaxBufferedBytes != tc.budget || next.Firewall.MaxBodyBytes != tc.body || next.HTTP.HTTP2Enable != tc.http2 || next.HTTP.IdleTimeout.String() != tc.idle {
							t.Fatalf("restart would not load saved buffer/body settings: %+v %v", next.Firewall, err)
						}
					}
				})
			}
		})
	}
}
