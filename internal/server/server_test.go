package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy-firewall/internal/admin"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/proxy"
)

func serverConfig(upstream string) config.Config {
	cfg := config.Defaults()
	cfg.HTTP.Listen, cfg.HTTP.TLSListen = "127.0.0.1:0", "127.0.0.1:0"
	cfg.HTTP.ReadTimeout, cfg.HTTP.WriteTimeout = time.Second, time.Second
	cfg.TLS.Enabled = false
	cfg.Observability.PprofAddress = ""
	cfg.Proxy.Upstream, cfg.Proxy.IPv4Redirect = upstream, ""
	cfg.Firewall.MaxBodyBytes, cfg.Firewall.MaxBufferedBytes = 1024, 4096
	return cfg
}

func newTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	return newServerForTest(t, cfg, false)
}

func newServerForTest(t *testing.T, cfg config.Config, withAdmin bool) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := firewall.New(cfg, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := proxy.New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	var stats *monitoring.Registry
	var adminUI *admin.Handler
	if withAdmin {
		stats = monitoring.New(cfg)
		adminUI, err = admin.New(cfg, stats, engine, logger)
		if err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(cfg, engine, upstream, logger, stats, adminUI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Stop(ctx); err != nil {
			t.Errorf("stop: %v", err)
		}
		_ = upstream.Close()
	})
	return server
}

func TestRawWireRejectsParserAmbiguitiesBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	s := newTestServer(t, serverConfig(upstream.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, method, headers, body string }{
		{"duplicate content type", "POST", "Content-Type: application/x-www-form-urlencoded\r\nContent-Type: application/json\r\n", "a=1"},
		{"multipart preamble", "POST", "Content-Type: multipart/form-data; boundary=b\r\n", "hidden\r\n--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\ny\r\n--b--\r\n"},
		{"extension method multipart", "CUSTOM", "Content-Type: multipart/form-data; boundary=b\r\n", "hidden\r\n--b--\r\n"},
		{"bodyless method payload", "GET", "Content-Type: application/x-www-form-urlencoded\r\n", "a=1"},
		{"compressed request", "POST", "Content-Type: application/octet-stream\r\nContent-Encoding: gzip\r\n", "not transparently decompressed"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", s.HTTPAddress().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = fmt.Fprintf(conn, "%s /Case%%2fSensitive//?q=%%2f HTTP/1.1\r\nHost: example.com\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", tt.method, tt.headers, len(tt.body), tt.body)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode < 400 || response.StatusCode >= 500 {
				t.Errorf("rejection status = %d", response.StatusCode)
			}
		})
	}
	if calls.Load() != 0 {
		t.Errorf("%d malformed requests reached upstream", calls.Load())
	}
}

func TestExtensionMethodPreservesRawRequest(t *testing.T) {
	const rawURL = "/MiXeD%2fPath//./a?q=%2f&plus=+"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "CUSTOM" || r.RequestURI != rawURL || len(body) != 0 {
			t.Errorf("upstream request = %s %q %q", r.Method, r.RequestURI, body)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	s := newTestServer(t, serverConfig(upstream.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("CUSTOM", "http://"+s.HTTPAddress().String()+rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status = %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
}

func TestPartialBindFailureReleasesEarlierListener(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	available, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddress := available.Addr().String()
	_ = available.Close()
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.HTTP.Listen, cfg.HTTP.TLSListen, cfg.TLS.Enabled = httpAddress, occupied.Addr().String(), true
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected TLS bind failure")
	}
	listener, err := net.Listen("tcp", httpAddress)
	if err != nil {
		t.Fatalf("HTTP listener leaked after failed start: %v", err)
	}
	_ = listener.Close()
}

func TestShutdownDrainsInFlightRequest(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "finished")
	}))
	defer upstream.Close()
	defer releaseOnce.Do(func() { close(release) })
	s := newTestServer(t, serverConfig(upstream.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	response := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + s.HTTPAddress().String())
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			err = readErr
			if string(data) != "finished" {
				err = fmt.Errorf("response body = %q", data)
			}
		}
		response <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach upstream")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(ctx) }()
	select {
	case err := <-stopped:
		t.Fatalf("shutdown returned before the active request finished: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", s.HTTPAddress().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Error("listener still accepted after shutdown")
	}
}

func TestImmediateStopAndRuntimeErrorSignal(t *testing.T) {
	for range 5 {
		s := newTestServer(t, serverConfig("http://127.0.0.1:1"))
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := s.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	s := newTestServer(t, serverConfig("http://127.0.0.1:1"))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = s.listeners[0].Close()
	select {
	case err := <-s.Errors():
		if err == nil {
			t.Error("nil runtime failure")
		}
	case <-time.After(time.Second):
		t.Fatal("missing listener failure signal")
	}
}

func TestHostPolicyAndAdminBinding(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]", "192.0.2.1:443"} {
		if err := hostPolicy(nil)(context.Background(), host); err == nil {
			t.Errorf("allowed IP certificate: %s", host)
		}
	}
	policy := hostPolicy([]string{"example.com"})
	if err := policy(context.Background(), "example.com."); err != nil {
		t.Error(err)
	}
	if err := policy(context.Background(), "other.example"); err == nil {
		t.Error("allowed unconfigured host")
	}
	for _, address := range []string{"0.0.0.0:8068", ":8068", "localhost:8068", "192.0.2.1:8068"} {
		if _, err := newAdminServer(address); err == nil {
			t.Errorf("accepted non-loopback pprof address %q", address)
		}
	}
	if _, err := newAdminServer("127.0.0.1:0"); err != nil {
		t.Error(err)
	}
}
