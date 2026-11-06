package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlacklistedHostnameReturnsConflictPage(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "upstream") }))
	defer backend.Close()
	s := newTestServer(t, serverConfig(backend.URL))
	s.certGuard.file = filepath.Join(t.TempDir(), certificateBlacklistFile)
	s.certGuard.blacklist["blocked.example"] = time.Now().Add(time.Hour)
	s.certGuard.blacklist["expired.example"] = time.Now().Add(-time.Hour)
	for _, tt := range []struct {
		method, host, path string
		status             int
	}{
		{"GET", "BLOCKED.EXAMPLE.:80", "/", 409},
		{"HEAD", "blocked.example", "/", 409},
		{"GET", "blocked.example", "/__pf/__admin/dns/test", 409},
		{"GET", "expired.example", "/", 200},
		{"GET", "other.example", "/", 200},
	} {
		r := httptest.NewRequest(tt.method, "http://"+tt.host+tt.path, nil)
		response, err := s.app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tt.status {
			t.Fatalf("%s %s status=%d want=%d", tt.method, tt.host, response.StatusCode, tt.status)
		}
		if tt.status == 409 {
			if response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(response.Header.Get("Content-Type"), "text/html") {
				t.Fatal("conflict page headers missing")
			}
			if tt.method == "HEAD" && len(body) != 0 {
				t.Fatal("HEAD returned a body")
			}
			if tt.method != "HEAD" && (!strings.Contains(string(body), "Hostname blacklisted") || !strings.Contains(string(body), "Make sure requested domain points to current server")) {
				t.Fatal("conflict page message missing")
			}
		}
	}
	if calls.Load() != 2 {
		t.Fatal("blacklisted requests reached upstream")
	}
	if err := s.certGuard.RemoveCertificateBlacklistHost("blocked.example"); err != nil {
		t.Fatal(err)
	}
}
