package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertificateListExcludesKeysAccountsAndChallengeFiles(t *testing.T) {
	cert, key, _ := certificateFiles(t)
	certData, _ := os.ReadFile(cert)
	keyData, _ := os.ReadFile(key)
	dir := t.TempDir()
	for name, data := range map[string][]byte{"site.example": append(append([]byte{}, keyData...), certData...), "site.example+token": certData, "acme_account+key": keyData} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(cert, filepath.Join(dir, "linked.example")); err != nil {
		t.Fatal(err)
	}
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.TLS.CacheDir = dir
	s := newTestServer(t, cfg)
	entries, err := s.CertificateEntries()
	if err != nil || len(entries) != 1 || entries[0].Hostname != "site.example" || entries[0].Source != "automatic" || entries[0].Expires.IsZero() {
		t.Fatalf("certificate list=%+v err=%v", entries, err)
	}
	if s.CanRequestCertificate() {
		t.Fatal("manual requests available with TLS disabled")
	}
}

func TestCloudflareExclusionPreservesExistingValidCertificate(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.TLS.Enabled, cfg.TLS.CacheDir = true, t.TempDir()
	s := newTestServer(t, cfg)
	cert, key, _ := certificateFilesForHost(t, "site.example")
	certData, _ := os.ReadFile(cert)
	keyData, _ := os.ReadFile(key)
	if err := os.WriteFile(filepath.Join(cfg.TLS.CacheDir, "site.example"), append(keyData, certData...), 0600); err != nil {
		t.Fatal(err)
	}
	s.certGuard.behindCloudflare = func(string) bool { return true }
	s.certGuard.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("Cloudflare hostname was probed")
		return nil, nil
	})
	if err := s.manager.HostPolicy(context.Background(), "site.example"); err != nil {
		t.Fatal("existing valid certificate was blocked", err)
	}
	if err := s.manager.HostPolicy(context.Background(), "other.example"); !errors.Is(err, errCertificateCloudflare) {
		t.Fatal("uncached Cloudflare hostname passed admission", err)
	}
}

func TestManualCertificateRequestsRespectBlacklistAndVerification(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.TLS.Enabled = true
	cfg.TLS.CacheDir = t.TempDir()
	s := newTestServer(t, cfg)
	s.certGuard.file = filepath.Join(t.TempDir(), certificateBlacklistFile)
	s.certGuard.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { return certificateResponse(204, "wrong"), nil })
	s.certGuard.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	s.certGuard.localIPs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil }
	var calls atomic.Int64
	s.certIssue = func(string) error { calls.Add(1); return nil }
	s.certGuard.blacklist["site.example"] = time.Now().Add(time.Hour)
	if err := s.RequestCertificate("site.example"); err == nil {
		t.Fatal("manual request bypassed blacklist")
	}
	if err := s.certGuard.RemoveCertificateBlacklistHost("site.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestCertificate("site.example"); err != nil {
		t.Fatal(err)
	}
	awaitCertificateRequest(t, s, "issued")
	if calls.Load() != 1 {
		t.Fatal("manual certificate request did not reach issuer exactly once")
	}
	s.certGuard.behindCloudflare = func(string) bool { return true }
	if err := s.RequestCertificate("cloud.example"); !errors.Is(err, errCertificateCloudflare) {
		t.Fatal("Cloudflare hostname reached manual queue", err)
	}
	s.certGuard.behindCloudflare = nil
	s.certGuard.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.50")}, nil
	}
	s.certGuard.localIPs = func() ([]netip.Addr, error) { return nil, nil }
	if err := s.RequestCertificate("foreign.example"); err != nil {
		t.Fatal(err)
	}
	awaitCertificateRequest(t, s, "failed")
	if calls.Load() != 1 {
		t.Fatal("failed verification reached certificate issuer")
	}
	if entries := s.certGuard.CertificateBlacklistEntries(); len(entries) != 1 || entries[0].Hostname != "foreign.example" {
		t.Fatal("failed manual request was not blacklisted")
	}
}

func awaitCertificateRequest(t *testing.T, s *Server, status string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		for _, request := range s.CertificateRequests() {
			if request.Status == status {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("no %s certificate request: %+v", status, s.CertificateRequests())
		case <-ticker.C:
		}
	}
}

func TestCertificateAdmissionRejectsFakeSNIWithoutCARequest(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.TLS.Enabled = true
	cfg.TLS.CacheDir = t.TempDir()
	s := newTestServer(t, cfg)
	s.certGuard.file = filepath.Join(t.TempDir(), certificateBlacklistFile)
	s.certGuard.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { return certificateResponse(204, "wrong"), nil })
	s.certGuard.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.50")}, nil
	}
	s.certGuard.localIPs = func() ([]netip.Addr, error) { return nil, nil }
	var calls atomic.Int64
	s.manager.Client.HTTPClient.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, io.EOF })
	if err := s.manager.HostPolicy(context.Background(), "fake.example"); err == nil || calls.Load() != 0 {
		t.Fatal("fake hostname passed certificate policy")
	}
	if data, err := os.ReadFile(s.certGuard.file); err != nil || !strings.HasPrefix(string(data), "fake.example|expires:") {
		t.Fatal("fake SNI was not persisted", err)
	}
}

func TestCertbotAdminRemovalAndManualRequestUseCustomPrefix(t *testing.T) {
	cfg := adminConfig("http://127.0.0.1:1")
	cfg.Admin.URI = "ops/control"
	cfg.TLS.Enabled = true
	cfg.TLS.CacheDir = t.TempDir()
	s := newServerForTest(t, cfg, true)
	s.certGuard.file = filepath.Join(t.TempDir(), certificateBlacklistFile)
	s.certGuard.blacklist["site.example"] = time.Now().Add(time.Hour)
	s.certGuard.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { return certificateResponse(204, "wrong"), nil })
	s.certGuard.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	s.certGuard.localIPs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil }
	s.certIssue = func(string) error { return nil }
	for _, tt := range []struct {
		method, suffix string
		status         int
	}{
		{"GET", "certbot-blacklist", 200}, {"POST", "certificates?hostname=site.example", 400},
		{"DELETE", "certbot-blacklist?hostname=site.example", 200}, {"POST", "certificates?hostname=site.example", 202}, {"GET", "certificates", 200},
	} {
		r := httptest.NewRequest(tt.method, "http://admin.example/ops/control/api/"+tt.suffix, nil)
		r.SetBasicAuth("operator", "integration-test-password")
		r.Header.Set("X-PF-Admin", "1")
		response, err := s.app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tt.status {
			t.Fatalf("%s %s status=%d want=%d body=%s", tt.method, tt.suffix, response.StatusCode, tt.status, body)
		}
	}
	awaitCertificateRequest(t, s, "issued")
}
