package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

type certificateRoundTrip func(*http.Request) (*http.Response, error)

func (f certificateRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testCertificateGuard(t *testing.T) *certificateGuard {
	t.Helper()
	g, err := newCertificateGuard("/ops/control/dns/test", filepath.Join(t.TempDir(), certificateBlacklistFile), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.50")}, nil
	}
	g.localIPs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil }
	return g
}

func certificateResponse(status int, signature string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{dnsSignatureHeader: []string{signature}}, Body: io.NopCloser(strings.NewReader(""))}
}

func TestCertificateSignatureMustComeFromThisInstance(t *testing.T) {
	g := testCertificateGuard(t)
	app := fiber.New()
	app.Use(g.serve)
	var calls atomic.Int64
	g.client.Transport = certificateRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != "HEAD" || r.URL.Scheme != "http" || r.URL.Host != "site.example" || r.URL.Path != g.path || r.Header.Get(dnsSignatureHeader) != "" {
			t.Error("incorrect DNS probe request")
		}
		return app.Test(r)
	})
	if err := g.check(context.Background(), "SITE.EXAMPLE."); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("successful signature check retried")
	}
	if signature, ok := g.signatures.Get("site.example", g.now()); !ok || signature == "" {
		t.Fatal("hostname signature was not stored")
	}
	if err := g.check(context.Background(), "site.example"); err != nil || calls.Load() != 1 {
		t.Fatal("short successful cache was not reused")
	}
	if _, err := os.Stat(g.file); !os.IsNotExist(err) {
		t.Fatal("successful proof wrote a blacklist")
	}

	stale := testCertificateGuard(t)
	stale.signatures.Set("site.example", "old-signature", time.Now().Add(time.Minute), time.Now())
	stale.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { return certificateResponse(204, "old-signature"), nil })
	if err := stale.check(context.Background(), "site.example"); err == nil {
		t.Fatal("accepted a replayed signature")
	}
}

func TestCertificateDNSFallbackAndPersistentBlacklist(t *testing.T) {
	for _, tt := range []struct {
		name, address string
		local, allow  bool
	}{
		{"loopback", "127.0.0.1", true, false}, {"mapped loopback", "::ffff:127.0.0.1", true, false},
		{"IPv6 loopback", "::1", true, false}, {"private", "10.0.0.1", true, false},
		{"shared address", "100.64.0.1", true, false}, {"link local", "169.254.1.1", true, false},
		{"documentation", "203.0.113.1", true, false}, {"IPv6 documentation", "2001:db8::1", true, false},
		{"server IPv4", "8.8.8.8", true, true}, {"server IPv6", "2001:4860:4860::8888", true, true},
		{"foreign public", "1.1.1.1", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := testCertificateGuard(t)
			var calls atomic.Int64
			g.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return certificateResponse(204, "foreign-signature"), nil
			})
			g.lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				if calls.Load() != 3 || network != "ip" || host != "site.example" {
					t.Error("DNS fallback did not follow three HEAD attempts")
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
					t.Error("DNS lookup is not bounded")
				}
				return []netip.Addr{netip.MustParseAddr(tt.address)}, nil
			}
			g.localIPs = func() ([]netip.Addr, error) {
				if tt.local {
					return []netip.Addr{netip.MustParseAddr(tt.address)}, nil
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			before := time.Now()
			err := g.check(context.Background(), "site.example")
			if (err == nil) != tt.allow {
				t.Fatalf("allowed=%v, err=%v", tt.allow, err)
			}
			if tt.allow {
				return
			}
			data, err := os.ReadFile(g.file)
			if err != nil {
				t.Fatal(err)
			}
			_, expiry, ok := strings.Cut(strings.TrimSpace(string(data)), "site.example|expires:")
			until, err := time.Parse(time.RFC3339Nano, expiry)
			if !ok || err != nil || until.Before(before.Add(14*24*time.Hour)) || until.After(time.Now().Add(14*24*time.Hour)) {
				t.Fatalf("incorrect blacklist expiration: %q", data)
			}
			info, _ := os.Stat(g.file)
			if info.Mode().Perm() != 0600 {
				t.Fatal("blacklist is not private")
			}
			reloaded, err := newCertificateGuard(g.path, g.file, g.logger)
			if err != nil {
				t.Fatal(err)
			}
			reloaded.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("blacklisted hostname was probed")
				return nil, nil
			})
			if err := reloaded.check(context.Background(), "site.example"); err == nil {
				t.Fatal("restart lost blacklist")
			}
			if err := reloaded.RemoveCertificateBlacklistHost("SITE.EXAMPLE."); err != nil {
				t.Fatal(err)
			}
			if data, _ := os.ReadFile(g.file); len(data) != 0 {
				t.Fatal("removal was not persisted")
			}
		})
	}
}

func TestCertificateProbeTimeoutAndFallback(t *testing.T) {
	g := testCertificateGuard(t)
	var attempts atomic.Int64
	var maxElapsed atomic.Int64
	g.client.Transport = certificateRoundTrip(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		start := time.Now()
		<-r.Context().Done()
		elapsed := time.Since(start).Milliseconds()
		for old := maxElapsed.Load(); elapsed > old && !maxElapsed.CompareAndSwap(old, elapsed); old = maxElapsed.Load() {
		}
		return nil, r.Context().Err()
	})
	g.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	start := time.Now()
	if err := g.check(context.Background(), "site.example"); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 || maxElapsed.Load() > 1500 || time.Since(start) > 4*time.Second {
		t.Fatalf("attempts=%d maximum_ms=%d total=%s", attempts.Load(), maxElapsed.Load(), time.Since(start))
	}
}

func TestCertificateSingleFlightCancellationExpiryAndCloudflare(t *testing.T) {
	g := testCertificateGuard(t)
	app := fiber.New()
	app.Use(g.serve)
	start, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	g.client.Transport = certificateRoundTrip(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(start)
		}
		<-release
		return app.Test(r)
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.check(context.Background(), "site.example"); err != nil {
				t.Error(err)
			}
		}()
	}
	<-start
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.check(ctx, "site.example"); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation ignored")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent checks duplicated probes")
	}
	g.behindCloudflare = func(string) bool { return true }
	if err := g.check(context.Background(), "site.example"); !errors.Is(err, errCertificateCloudflare) {
		t.Fatal("cached success bypassed new Cloudflare rule")
	}
	if len(g.CertificateBlacklistEntries()) != 0 {
		t.Fatal("Cloudflare exclusion incorrectly added a blacklist entry")
	}
	g.behindCloudflare = nil
	g.blacklist["expired.example"] = time.Now().Add(-time.Hour)
	if err := g.check(context.Background(), "expired.example"); err != nil {
		t.Fatal("expired blacklist entry remained blocked", err)
	}
}

func TestDNSRoutePublicAndAdminPrefix(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.Admin.URI = "ops/control"
	s := newTestServer(t, cfg)
	for _, tt := range []struct {
		method, path, host string
		status             int
	}{
		{"HEAD", "/ops/control/dns/test", "SITE.EXAMPLE.", 204},
		{"GET", "/ops/control/dns/test", "site.example", 405},
		{"HEAD", "/ops/control/dns/test", "127.0.0.1", 400},
		{"HEAD", "/ops/control/api/certbot-blacklist", "site.example", 404},
	} {
		request := httptest.NewRequest(tt.method, "http://"+tt.host+tt.path, nil)
		response, err := s.app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tt.status {
			t.Fatalf("%s %s status=%d want=%d", tt.method, tt.path, response.StatusCode, tt.status)
		}
		if tt.status == 204 && (response.Header.Get(dnsSignatureHeader) == "" || response.Header.Get("WWW-Authenticate") != "") {
			t.Fatal("public DNS route requires login or lacks signature")
		}
	}
}

func TestACMERenewalOrdersAreGuardedBeforeNetwork(t *testing.T) {
	g := testCertificateGuard(t)
	g.behindCloudflare = func(string) bool { return true }
	var calls atomic.Int64
	transport := &certificateACMETransport{guard: g, next: certificateRoundTrip(func(*http.Request) (*http.Response, error) { calls.Add(1); return certificateResponse(200, ""), nil })}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"site.example"}]}`))
	request, _ := http.NewRequest("POST", "https://ca.example/new-order", strings.NewReader(fmt.Sprintf(`{"payload":%q}`, payload)))
	if _, err := transport.RoundTrip(request); !errors.Is(err, errCertificateCloudflare) || calls.Load() != 0 {
		t.Fatal("Cloudflare renewal reached the CA", err)
	}
	request, _ = http.NewRequest("POST", "https://ca.example/account", strings.NewReader(`{"payload":""}`))
	if _, err := transport.RoundTrip(request); err != nil || calls.Load() != 1 {
		t.Fatal("non-order ACME request was altered", err)
	}
}

func TestCertificateGuardErrorsAndLogsIncludeCanonicalHostname(t *testing.T) {
	var output strings.Builder
	g := testCertificateGuard(t)
	g.logger = slog.New(slog.NewTextHandler(&output, nil))
	g.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) { return certificateResponse(204, "wrong"), nil })
	err := g.check(context.Background(), "SITE.EXAMPLE.")
	if !errors.Is(err, errCertificateDNS) || !strings.Contains(err.Error(), "site.example") || !strings.Contains(output.String(), "hostname=site.example") {
		t.Fatalf("hostname context missing: %v %s", err, output.String())
	}
	err = g.check(context.Background(), "site.example")
	if !errors.Is(err, errCertificateBlacklisted) || !strings.Contains(err.Error(), "site.example") {
		t.Fatalf("blacklist error hostname missing: %v", err)
	}
	g.behindCloudflare = func(string) bool { return true }
	err = g.check(context.Background(), "cloud.example")
	if !errors.Is(err, errCertificateCloudflare) || !strings.Contains(err.Error(), "cloud.example") {
		t.Fatalf("Cloudflare error hostname missing: %v", err)
	}
}

func TestCertificateGuardRejectsInvalidHostnamesBeforeVerification(t *testing.T) {
	g := testCertificateGuard(t)
	g.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("invalid hostname reached HTTP verification")
		return nil, context.Canceled
	})
	g.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("invalid hostname reached DNS verification")
		return nil, context.Canceled
	}
	for _, host := range []string{"", "localhost", "123", "123.456", "1.2.3", "999.999.999.999", "127.0.0.1", "8.8.8.8:443", "[::1]:443", "2001:4860:4860::8888", ".example", "example..com", "a.-b", "a.b-", "example.com/path"} {
		if err := g.check(context.Background(), host); err == nil {
			t.Fatalf("invalid hostname accepted: %s", host)
		}
	}
	if len(g.blacklist) != 0 || len(g.pending) != 0 {
		t.Fatal("invalid hostname consumed guard state")
	}
	for _, host := range []string{"example.com", "123.example", "a-b.example", "WWW.Example.COM.:443"} {
		if _, err := certificateHostname(host); err != nil {
			t.Fatalf("valid hostname %s rejected: %v", host, err)
		}
	}
}
