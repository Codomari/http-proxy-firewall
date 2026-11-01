package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/fx"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/server"
)

func TestApplicationForwardsInspectedChunkedBody(t *testing.T) {
	payload := "--b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nexample\r\n--b--\r\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != payload || r.RequestURI != "/upload%2Fsafe.css?a=1&a=2&x=%2F" || r.Host != "example.test" || r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-Forwarded-Proto") != "http" {
			t.Errorf("forwarding changed request: uri=%q host=%q ip=%q body=%q", r.RequestURI, r.Host, r.Header.Get("X-Forwarded-For"), body)
		}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("accepted"))
	}))
	t.Cleanup(upstream.Close)
	address := startApplication(t, upstream.URL)
	// Hiding strings.Reader's Len forces chunked transfer encoding.
	request, err := http.NewRequest(http.MethodPost, address+"/upload%2Fsafe.css?a=1&a=2&x=%2F", struct{ io.Reader }{strings.NewReader(payload)})
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.test"
	request.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusCreated || string(body) != "accepted" || response.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("unexpected response: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
}

func TestApplicationEnforcesSecurityBeforeBypasses(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	address := startApplication(t, upstream.URL)
	progress := "--b\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n--b--\r\n"
	for _, tt := range []struct {
		method, path, body, contentType, encoding, agent string
		status                                           int
	}{
		{method: "POST", path: "/style.css", body: progress, contentType: "multipart/form-data; boundary=b", status: 403},
		{method: "GET", path: "/image.png", body: "body", status: 400},
		{method: "POST", path: "/style.css", body: "broken", contentType: "multipart/form-data; boundary=b", status: 400},
		{method: "POST", path: "/index.php", body: "compressed", encoding: "gzip", status: 415},
		{method: "GET", path: "/style.css?password=", agent: "Googlebot", status: 403},
	} {
		t.Run(tt.method+tt.path+tt.encoding, func(t *testing.T) {
			request, err := http.NewRequest(tt.method, address+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "example.test"
			if tt.contentType != "" {
				request.Header.Set("Content-Type", tt.contentType)
			}
			if tt.encoding != "" {
				request.Header.Set("Content-Encoding", tt.encoding)
			}
			if tt.agent != "" {
				request.Header.Set("User-Agent", tt.agent)
			}
			response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != tt.status {
				t.Fatalf("got status %d, expected %d", response.StatusCode, tt.status)
			}
		})
	}
	if got := forwarded.Load(); got != 0 {
		t.Fatalf("%d rejected requests reached upstream", got)
	}
}

func TestApplicationServesEmbeddedAdminAndTracksProxyOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("origin")) }))
	t.Cleanup(upstream.Close)
	address := startApplication(t, upstream.URL, func(cfg *config.Config) {
		cfg.Admin = config.Admin{Enabled: true, User: "operator", Password: "test-password", MaxHosts: 32}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, address+"/index.css", nil)
	request.Host = "WWW.Example.test:8080"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("proxy status %d", response.StatusCode)
	}
	response, err = client.Get(address + "/__pf/__admin/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("anonymous admin status %d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodGet, address+"/__pf/__admin/api/overview", nil)
	request.SetBasicAuth("operator", "test-password")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var snapshot struct {
		Totals struct{ Requests, Inflight uint64 }
		Hosts  []struct {
			Hostname           string
			Requests, Inflight uint64
		}
	}
	if response.StatusCode != 200 {
		t.Fatalf("authenticated admin status %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Totals.Requests != 1 || snapshot.Totals.Inflight != 0 || len(snapshot.Hosts) != 1 || snapshot.Hosts[0].Hostname != "www.example.test" || snapshot.Hosts[0].Requests != 1 || snapshot.Hosts[0].Inflight != 0 {
		t.Fatalf("wrong proxy-only snapshot: %+v", snapshot)
	}
}

func startApplication(t *testing.T, upstream string, changes ...func(*config.Config)) string {
	t.Helper()
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.TLS.Enabled = false
	cfg.Proxy.Upstream = upstream
	cfg.Proxy.IPv4Redirect = ""
	cfg.Observability.PprofAddress = ""
	cfg.Intelligence.GoogleRangesURL = ""
	cfg.Intelligence.DatabasePath = t.TempDir() + "/missing.mmdb"
	for _, change := range changes {
		change(&cfg)
	}
	var listener *server.Server
	application := New(cfg, fx.NopLogger, fx.Replace(slog.New(slog.NewTextHandler(io.Discard, nil))), fx.Populate(&listener))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := application.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := application.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return "http://" + listener.HTTPAddress().String()
}
