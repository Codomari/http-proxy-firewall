package admin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"
)

func TestRestartRequiresPendingSettingsAndSameOriginAdmin(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	h, err := New(cfg, monitoring.New(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.generalFile.Path = filepath.Join(t.TempDir(), config.OverrideYAML)
	calls := 0
	h.SetRestartHandler(func() error { calls++; return nil })
	app := fiber.New()
	h.Mount(app)
	call := func(method string, auth, csrf bool, site string, want int) restartSnapshot {
		t.Helper()
		r := httptest.NewRequest(method, "http://admin.test"+BasePath+"/api/restart", nil)
		if auth {
			r.Header.Set("Authorization", validBasic())
		}
		if csrf {
			r.Header.Set("X-PF-Admin", "1")
		}
		r.Header.Set("Sec-Fetch-Site", site)
		response, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s status=%d want=%d", method, response.StatusCode, want)
		}
		var state restartSnapshot
		if want == 200 || want == 202 {
			if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
				t.Fatal(err)
			}
		}
		return state
	}
	call("POST", false, true, "", 401)
	call("POST", true, false, "", 403)
	call("POST", true, true, "cross-site", 403)
	call("GET", true, true, "", 405)
	if call("POST", true, true, "same-origin", 200).Required || calls != 0 {
		t.Fatal("unnecessary restart executed")
	}
	rules, err := h.generalFile.Read()
	if err != nil {
		t.Fatal(err)
	}
	rules.GCMemoryLimit = "512MiB"
	if err := h.generalFile.Save(rules); err != nil {
		t.Fatal(err)
	}
	if !h.restartStatus().Required {
		t.Fatal("YAML GC edit did not require a restart")
	}
	rules.GCMemoryLimit = "off"
	if err := h.generalFile.Save(rules); err != nil {
		t.Fatal(err)
	}
	if call("POST", true, true, "same-origin", 200).Required || calls != 0 {
		t.Fatal("stale restart action restarted after reverting settings")
	}
	if err := os.WriteFile(h.generalFile.Path, []byte("env: [invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	call("POST", true, true, "same-origin", 503)
	if calls != 0 {
		t.Fatal("invalid configuration restarted")
	}
	if err := os.WriteFile(h.generalFile.Path, []byte("env: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules.GCMemoryLimit = "512MiB"
	if err := h.generalFile.Save(rules); err != nil {
		t.Fatal(err)
	}
	if !call("POST", true, true, "same-origin", 202).Restarting || calls != 1 {
		t.Fatal("pending GC settings did not restart")
	}
	call("POST", true, true, "same-origin", 200)
	if calls != 1 {
		t.Fatal("duplicate restart executed")
	}
}
