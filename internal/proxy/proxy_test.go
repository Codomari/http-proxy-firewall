package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func testConfig(upstream string) config.Config {
	return config.Config{Proxy: config.Proxy{Upstream: upstream, MaxConnections: 2, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Minute}}
}

func frontend(t *testing.T, cfg config.Config) (string, *Handler) {
	t.Helper()
	return frontendWithListener(t, cfg, nil)
}

func frontendWithListener(t *testing.T, cfg config.Config, wrap func(net.Listener) net.Listener, middleware ...fiber.Handler) (string, *Handler) {
	t.Helper()
	h, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{DisablePreParseMultipartForm: true, CaseSensitive: true, StrictRouting: true})
	for _, handler := range middleware {
		app.Use(handler)
	}
	app.Use(h.Handle)
	app.Handler()
	app.Server().ConnState = func(conn net.Conn, state fasthttp.ConnState) {
		if state == fasthttp.StateClosed {
			h.AbortPendingUpgrade(conn)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if wrap != nil {
		listener = wrap(listener)
	}
	done := make(chan error, 1)
	go func() { done <- app.Server().Serve(listener) }()
	t.Cleanup(func() {
		_ = h.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = app.ShutdownWithContext(ctx)
		_ = listener.Close()
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("frontend did not stop")
		}
	})
	return "http://" + listener.Addr().String(), h
}

func TestForwardingPreservesRawURLHostBodyAndKeepalive(t *testing.T) {
	const rawURL = "/a%2fb//./C?x=%2f&x=1+2&empty="
	const body = "raw=one+two&binary=\x00\xff"
	var connections atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.RequestURI != rawURL || r.Host != "Tenant.Example:8443" || string(data) != body {
			t.Errorf("forwarded request: uri=%q host=%q body=%q", r.RequestURI, r.Host, data)
		}
		if r.Header.Get("X-Private") != "" || r.Header.Get("Connection") != "" {
			t.Errorf("hop headers were forwarded: %v", r.Header)
		}
		if r.Header.Get("X-Forwarded-For") == "spoofed" || r.Header.Get("CF-Connecting-IP") != "" {
			t.Error("untrusted identity forwarded")
		}
		if r.Header.Get("X-Forwarded-Host") != "Tenant.Example:8443" || r.Header.Get("X-Forwarded-Proto") != "http" {
			t.Error("missing forwarded origin")
		}
		w.Header().Set("Connection", "X-Upstream-Private")
		w.Header().Set("X-Upstream-Private", "remove")
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	address, _ := frontend(t, testConfig(upstream.URL))
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for i := range 2 {
		req, err := http.NewRequest(http.MethodPost, address+rawURL, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "Tenant.Example:8443"
		req.Header.Set("Connection", "X-Private, keep-alive")
		req.Header.Set("X-Private", "remove")
		req.Header.Set("X-Forwarded-For", "spoofed")
		req.Header.Set("CF-Connecting-IP", "spoofed")
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(data) != "ok" || resp.StatusCode != 200 {
			t.Fatalf("response: %d %q %v", resp.StatusCode, data, err)
		}
		if resp.Header.Get("X-Upstream-Private") != "" || resp.Close {
			t.Error("upstream hop headers affected frontend")
		}
		if i == 1 && !reused {
			t.Error("frontend connection was not reused")
		}
	}
	if got := connections.Load(); got != 1 {
		t.Errorf("upstream accepted %d connections; want one reused connection", got)
	}
}

func TestResponseStreamsBeforeUpstreamCompletes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "last\n")
	}))
	defer upstream.Close()
	defer close(release)
	address, _ := frontend(t, testConfig(upstream.URL))
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(address + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("first chunk = %q, %v", line, err)
	}
}

func TestUpstreamTimeoutDoesNotRetryPost(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL)
	cfg.Proxy.ReadTimeout = 50 * time.Millisecond
	address, _ := frontend(t, cfg)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Post(address, "text/plain", strings.NewReader("action"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d; want 504", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("POST attempts = %d; want 1", got)
	}
}

func TestBackendConnectionLimitReturns503(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	defer releaseOnce.Do(func() { close(release) })
	cfg := testConfig(upstream.URL)
	cfg.Proxy.MaxConnections = 1
	address, _ := frontend(t, cfg)
	first := make(chan error, 1)
	go func() {
		resp, err := http.Get(address)
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		first <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request never reached upstream")
	}
	resp, err := (&http.Client{Timeout: time.Second}).Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("pool-full response = %d %v", resp.StatusCode, resp.Header)
	}
	// Release before cleanup waits for active handlers.
	releaseOnce.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketUpgradePreservesBufferedBytesAndTunnels(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("missing websocket upgrade")
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nready")
		_ = rw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rw, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}))
	defer upstream.Close()
	address, _ := frontend(t, testConfig(upstream.URL))
	conn, err := net.Dial("tcp", strings.TrimPrefix(address, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprint(conn, "GET /chat?x=%2f HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test\r\nSec-WebSocket-Version: 13\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Server") != config.ServerName {
		t.Fatalf("upgrade leaked upstream server header: %q", resp.Header.Get("Server"))
	}
	data := make([]byte, 5)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ready" {
		t.Fatalf("buffered upgrade data = %q, %v", data, err)
	}
	_, _ = io.WriteString(conn, "ping")
	data = data[:4]
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ping" {
		t.Fatalf("tunneled echo = %q, %v", data, err)
	}
}

func TestInvalidUpstreams(t *testing.T) {
	for _, address := range []string{"", "ftp://example.com", "http://u:p@example.com", "http://example.com/path", "http://example.com?query=1"} {
		if _, err := New(testConfig(address), nil); err == nil {
			t.Errorf("accepted invalid upstream %q", address)
		}
	}
}
