package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
)

func TestRequestTooLargePageAndLiveBodyLimitOnHTTP1(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/origin-413" {
			http.Error(w, "origin limit", 413)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	}))
	defer backend.Close()
	cfg := adminConfig(backend.URL)
	root := t.TempDir()
	cfg.Source = config.NewYAMLStore(filepath.Join(root, config.DefaultYAML), filepath.Join(root, config.OverrideYAML))
	if err := cfg.Source.UpdateEnvironment(map[string]string{"CVE_MITIGATOR_MAX_BODY_BYTES": "1024", "PF_MAX_BUFFERED_BYTES": "4096"}); err != nil {
		t.Fatal(err)
	}
	s := newServerForTest(t, cfg, true)
	s.statusCountry = func(fiber.Ctx) string { return "Turkey" }
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	base := "http://" + s.HTTPAddress().String()
	request := func(body string, chunked bool, media string) (*http.Response, []byte) {
		t.Helper()
		var reader io.Reader = strings.NewReader(body)
		if chunked {
			reader = struct{ io.Reader }{reader}
		}
		r, _ := http.NewRequest("POST", base+"/upload", reader)
		r.Header.Set("Content-Type", media)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response, data
	}
	for _, chunked := range []bool{false, true} {
		response, body := request(strings.Repeat("x", 1025), chunked, "application/octet-stream")
		if response.StatusCode != 413 || response.Header.Get("Content-Language") != "tr" || response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(response.Header.Get("Content-Type"), "text/html") || !strings.Contains(response.Header.Get("Content-Security-Policy"), assetHash(statusLanguageJS)) || !response.Close {
			t.Fatalf("413 headers missing: %+v", response)
		}
		for _, want := range []string{`<small>413</small>`, `id="status-language"`, "1 KiB"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Fatalf("413 page missing %q", want)
			}
		}
		if bytes.Contains(body, []byte("{limit}")) {
			t.Fatal("unexpanded body limit")
		}
		response, _ = request(strings.Repeat("x", 1024), chunked, "application/octet-stream")
		if response.StatusCode != 204 {
			t.Fatalf("exact body limit rejected: %d", response.StatusCode)
		}
	}
	response, body := request(strings.Repeat("x[", 17)+"=1", false, "application/x-www-form-urlencoded")
	if response.StatusCode != 413 || !strings.Contains(string(body), `data-i18n="input_limit_message"`) {
		t.Fatal("form input limit incorrectly described as a byte limit")
	}
	// Saving must raise the live limit beyond Fiber's original streaming threshold.
	settings := config.GeneralRulesFromFirewall(cfg.Firewall)
	settings.MaxBodyBytes = 2048
	payload, _ := json.Marshal(settings)
	r, _ := http.NewRequest("POST", base+"/__pf/__admin/api/general-rules", bytes.NewReader(payload))
	r.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
	r.Header.Set("X-PF-Admin", "1")
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || s.bodyLimit() != 2048 {
		t.Fatalf("live save failed: %d %s", response.StatusCode, data)
	}
	for _, chunked := range []bool{false, true} {
		response, _ = request(strings.Repeat("x", 2048), chunked, "application/octet-stream")
		if response.StatusCode != 204 {
			t.Fatalf("raised limit rejected: %d", response.StatusCode)
		}
		response, body = request(strings.Repeat("x", 2049), chunked, "application/octet-stream")
		if response.StatusCode != 413 || !strings.Contains(string(body), "2 KiB") {
			t.Fatal("raised limit not reflected in 413 page")
		}
	}
	response, err = client.Get(base + "/origin-413")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 413 || string(body) != "origin limit\n" {
		t.Fatal("upstream 413 response was changed")
	}
	if calls.Load() != 5 {
		t.Fatalf("rejected request reached upstream: calls=%d", calls.Load())
	}
}
