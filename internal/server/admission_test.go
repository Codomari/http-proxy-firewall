package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
)

func TestAdminSaveChangesLiveRequestAndUpstreamLimits(t *testing.T) {
	hold := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	}))
	defer backend.Close()
	defer close(hold)
	cfg := adminConfig(backend.URL)
	cfg.Source = config.NewYAMLStore(filepath.Join(t.TempDir(), config.DefaultYAML), filepath.Join(t.TempDir(), config.OverrideYAML))
	s := newServerForTest(t, cfg, true)
	settings := config.GeneralRulesFromFirewall(cfg.Firewall)
	settings.DDoSThreshold = 200
	settings.ConnectionLimits = config.ConnectionLimits{MaxConcurrentRequests: 2, UpstreamMaxConnections: 1, UpstreamAllowOverflow: true, UpstreamMaxOverflowConnections: 3}
	data, _ := json.Marshal(settings)
	r := httptest.NewRequest("POST", "http://admin.example/__pf/__admin/api/general-rules", strings.NewReader(string(data)))
	r.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-PF-Admin", "1")
	response, err := s.app.Test(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("admin save failed", response.Status)
	}
	if s.admission.limit != 2 {
		t.Fatal("admin settings did not reach live request admission")
	}
	if !s.admission.acquire() || !s.admission.acquire() || s.admission.acquire() {
		t.Fatal("live request admission did not use the saved limit")
	}
	settings.MaxConcurrentRequests = 1
	s.SetConnectionLimits(settings.ConnectionLimits)
	if s.admission.acquire() {
		t.Fatal("request admitted while a lower limit was draining")
	}
	s.admission.release()
	if s.admission.acquire() {
		t.Fatal("request admitted at the reduced limit")
	}
	s.admission.release()
	if !s.admission.acquire() {
		t.Fatal("capacity did not recover after draining")
	}
	s.admission.release()
	document, err := cfg.Source.Read()
	if err != nil {
		t.Fatal(err)
	}
	values := document.Environment()
	for key, want := range map[string]string{"PF_MAX_CONCURRENT_REQUESTS": "2", "PF_UPSTREAM_MAX_CONNECTIONS": "1", "PF_UPSTREAM_ALLOW_OVERFLOW": "true", "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "3"} {
		if values[key] != want {
			t.Fatalf("saved %s=%s want=%s", key, values[key], want)
		}
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for range 3 {
		response, err := client.Get("http://" + s.HTTPAddress().String() + "/stream")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("admin overflow settings did not reach the running proxy", response.Status)
		}
	}
	blocked, err := client.Get("http://" + s.HTTPAddress().String() + "/ceiling")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Body.Close()
	body, err := io.ReadAll(blocked.Body)
	if err != nil || blocked.StatusCode != 503 || blocked.Header.Get("Retry-After") != "1" || !strings.Contains(string(body), `data-page="service-unavailable"`) {
		t.Fatal("running proxy lost the overflow rejection page or retry guidance")
	}
}
