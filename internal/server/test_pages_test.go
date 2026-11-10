package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/admin"
)

func TestStatusPreviewsRequireAdminAndDoNotChangeServerState(t *testing.T) {
	var upstreamCalls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(200) }))
	defer backend.Close()
	cfg := adminConfig(backend.URL)
	cfg.Admin.URI = "ops/control"
	s := newServerForTest(t, cfg, true)
	s.statusCountry = func(fiber.Ctx) string { return "Ukraine" }
	for _, tc := range []struct {
		path, method string
		auth         bool
		status       int
	}{
		{"server-error", "GET", false, 401}, {"server-error", "GET", true, 500}, {"server-error", "HEAD", true, 500}, {"server-error", "POST", true, 405},
		{"bad-gateway", "GET", false, 401}, {"bad-gateway", "GET", true, 502}, {"bad-gateway", "HEAD", true, 502}, {"bad-gateway", "POST", true, 405},
		{"service-unavailable", "GET", false, 401}, {"service-unavailable", "GET", true, 503}, {"service-unavailable", "HEAD", true, 503}, {"service-unavailable", "POST", true, 405},
		{"request-too-large", "GET", false, 401}, {"request-too-large", "GET", true, 413}, {"request-too-large", "HEAD", true, 413}, {"request-too-large", "POST", true, 405}, {"restart", "GET", false, 401}, {"blocked-hostname", "GET", false, 401}, {"tls-hostname", "GET", false, 401},
		{"restart", "GET", true, 540}, {"restart", "HEAD", true, 540},
		{"blocked-hostname", "GET", true, 409}, {"blocked-hostname", "HEAD", true, 409},
		{"tls-hostname", "GET", true, 409}, {"tls-hostname", "HEAD", true, 409},
		{"restart", "POST", true, 405}, {"unknown", "GET", true, 404},
	} {
		r := httptest.NewRequest(tc.method, "http://admin.example/ops/control/test/pages/"+tc.path, nil)
		if tc.auth {
			r.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
		}
		response, err := s.app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s %s status=%d want=%d", tc.method, tc.path, response.StatusCode, tc.status)
		}
		if tc.status == 540 || tc.status == 409 || tc.status == 413 || tc.status == 500 || tc.status == 502 || tc.status == 503 {
			if response.Header.Get("Content-Language") != "uk" || response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(response.Header.Get("Content-Security-Policy"), assetHash(statusLanguageJS)) {
				t.Fatal("preview security/localization headers missing")
			}
			if tc.method == "HEAD" {
				if len(body) != 0 {
					t.Fatal("HEAD preview returned a body")
				}
			} else if !strings.Contains(string(body), `id="status-language"`) {
				t.Fatal("preview language selector missing")
			}
		}
	}
	r := httptest.NewRequest("GET", "http://admin.example/ops/control/api/test-pages", nil)
	r.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
	response, err := s.app.Test(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var index struct {
		Pages []admin.TestPage `json:"pages"`
	}
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&index) != nil || len(index.Pages) != 7 {
		t.Fatal("preview index missing registered pages")
	}
	if s.restarting.Load() || len(s.certGuard.blacklist) != 0 || upstreamCalls.Load() != 0 {
		t.Fatal("preview changed server state or called upstream")
	}
}
