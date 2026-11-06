package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
)

func waitConnections(t *testing.T, h *Handler, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for h.client.ConnsCount() != want {
		if time.Now().After(deadline) {
			t.Fatalf("connections=%d want=%d", h.client.ConnsCount(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOverflowReachesCeilingAndClosesWhileNormalKeepaliveSurvives(t *testing.T) {
	releaseBase, releaseOverflow := make(chan struct{}), make(chan struct{})
	var baseOnce, overflowOnce sync.Once
	var opened atomic.Int64
	type seenRequest struct {
		path, remote string
		close        bool
	}
	seen := make(chan seenRequest, 4)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- seenRequest{r.URL.Path, r.RemoteAddr, r.Close}
		if r.URL.Path == "/base" || r.URL.Path == "/overflow" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			hold := releaseBase
			if r.URL.Path == "/overflow" {
				hold = releaseOverflow
			}
			select {
			case <-hold:
			case <-r.Context().Done():
			}
		}
		_, _ = io.WriteString(w, "done\n")
	}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	backend.Start()
	defer backend.Close()
	defer baseOnce.Do(func() { close(releaseBase) })
	defer overflowOnce.Do(func() { close(releaseOverflow) })
	cfg := testConfig(backend.URL)
	cfg.Proxy.MaxConnections, cfg.Proxy.AllowOverflow, cfg.Proxy.MaxOverflowConnections = 1, true, 2
	address, h := frontend(t, cfg)
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
	first, err := client.Get(address + "/base")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	base := <-seen
	second, err := client.Get(address + "/overflow")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	overflow := <-seen
	if base.close || !overflow.close || base.remote == overflow.remote {
		t.Fatal("overflow did not use a disposable extra connection")
	}
	if first.Close || second.Close {
		t.Fatal("upstream overflow close leaked to the downstream keepalive")
	}
	if h.slots.InUse() != 2 || h.client.ConnsCount() != 2 {
		t.Fatal("burst did not grow to its absolute ceiling")
	}
	rejected, err := client.Get(address + "/ceiling")
	if err != nil {
		t.Fatal(err)
	}
	rejected.Body.Close()
	if rejected.StatusCode != 503 || opened.Load() != 2 {
		t.Fatal("burst exceeded its hard ceiling")
	}
	overflowOnce.Do(func() { close(releaseOverflow) })
	_, _ = io.Copy(io.Discard, second.Body)
	second.Body.Close()
	waitConnections(t, h, 1)
	baseOnce.Do(func() { close(releaseBase) })
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	waitConnections(t, h, 1)
	final, err := client.Get(address + "/reuse")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, final.Body)
	final.Body.Close()
	reused := <-seen
	if reused.remote != base.remote || reused.close || opened.Load() != 2 {
		t.Fatal("normal pool keepalive was discarded or overflow was retained")
	}
	deadline := time.Now().Add(time.Second)
	for h.slots.InUse() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("burst retained request slots")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLiveConnectionLimitsApplyToRoutesAndDrainReservations(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:8008")
	cfg.Proxy.Routes = map[string]string{"route.example": "http://127.0.0.1:8009"}
	h, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	limits := config.ConnectionLimits{MaxConcurrentRequests: 8, UpstreamMaxConnections: 1, UpstreamAllowOverflow: true, UpstreamMaxOverflowConnections: 3}
	h.SetConnectionLimits(limits)
	for _, pool := range []*Handler{h, h.routes["route.example"]} {
		first, ok := pool.slots.acquire()
		if !ok || first {
			t.Fatal("base capacity unavailable")
		}
		second, ok := pool.slots.acquire()
		if !ok || !second {
			t.Fatal("first overflow unavailable")
		}
		third, ok := pool.slots.acquire()
		if !ok || !third {
			t.Fatal("second overflow unavailable")
		}
		if _, ok := pool.slots.acquire(); ok {
			t.Fatal("admitted beyond absolute ceiling")
		}
	}
	limits.UpstreamAllowOverflow = false
	h.SetConnectionLimits(limits)
	for _, pool := range []*Handler{h, h.routes["route.example"]} {
		if pool.slots.InUse() != 3 {
			t.Fatal("lowering the limit lost active reservations")
		}
		if _, ok := pool.slots.acquire(); ok {
			t.Fatal("lowered limit admitted new work while draining")
		}
		pool.slots.release(true)
		pool.slots.release(true)
		if _, ok := pool.slots.acquire(); ok {
			t.Fatal("overflow disable bypassed normal limit")
		}
		pool.slots.release(false)
		if extra, ok := pool.slots.acquire(); !ok || extra {
			t.Fatal("normal capacity did not recover after draining")
		}
		pool.slots.release(false)
	}
}

func TestConcurrentConnectionLimitUpdatesAndTraffic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	address, h := frontend(t, testConfig(backend.URL))
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 100 {
			h.SetConnectionLimits(config.ConnectionLimits{MaxConcurrentRequests: 8, UpstreamMaxConnections: 1 + i%3, UpstreamAllowOverflow: i%2 == 0, UpstreamMaxOverflowConnections: 4})
		}
	})
	for range 4 {
		wg.Go(func() {
			client := &http.Client{Timeout: 2 * time.Second}
			for range 20 {
				r, err := client.Get(address)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				r.Body.Close()
				if r.StatusCode != 200 && r.StatusCode != 503 {
					t.Errorf("unexpected status %d", r.StatusCode)
				}
			}
		})
	}
	wg.Wait()
}

func TestLowerNormalLimitDrainsActiveStreamsAndTrimsIdleConnections(t *testing.T) {
	hold := make(chan struct{})
	var once sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-hold
		io.WriteString(w, "last\n")
	}))
	defer backend.Close()
	defer once.Do(func() { close(hold) })
	cfg := testConfig(backend.URL)
	cfg.Proxy.MaxConnections = 2
	address, h := frontend(t, cfg)
	client := &http.Client{Timeout: 2 * time.Second}
	first, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	second, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	h.SetConnectionLimits(config.ConnectionLimits{UpstreamMaxConnections: 1})
	if h.slots.InUse() != 2 || h.client.ConnsCount() != 2 {
		t.Fatal("lowering capacity interrupted active streams")
	}
	blocked, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != 503 {
		t.Fatal("new work was admitted above the reduced limit")
	}
	once.Do(func() { close(hold) })
	for _, response := range []*http.Response{first, second} {
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "first\nlast\n" {
			t.Fatal("active stream was truncated during resizing", err, string(body))
		}
	}
	deadline := time.Now().Add(time.Second)
	for h.client.ConnsCount() > 1 {
		if time.Now().After(deadline) {
			t.Fatal("surplus idle connections survived a reduction")
		}
		time.Sleep(time.Millisecond)
	}
	after, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, after.Body)
	after.Body.Close()
	waitConnections(t, h, 1)
}

func TestOverflowSharesCeilingWithUpgradedTunnelsAndIdlePool(t *testing.T) {
	hold := make(chan struct{})
	var once sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "private.v1" {
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\n")
			rw.Flush()
			io.Copy(io.Discard, rw)
			return
		}
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			select {
			case <-hold:
			case <-r.Context().Done():
			}
		}
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	defer once.Do(func() { close(hold) })
	cfg := testConfig(backend.URL)
	cfg.Proxy.MaxConnections, cfg.Proxy.AllowOverflow, cfg.Proxy.MaxOverflowConnections = 1, true, 2
	address, h := frontend(t, cfg)
	client := &http.Client{Timeout: 2 * time.Second}
	warm, err := client.Get(address + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, warm.Body)
	warm.Body.Close()
	waitConnections(t, h, 1)
	deadline := time.Now().Add(time.Second)
	for h.slots.InUse() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("warmup retained a slot")
		}
		time.Sleep(time.Millisecond)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(address, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\n")
	upgraded, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || upgraded.StatusCode != 101 {
		t.Fatal("upgrade failed", err)
	}
	waitConnections(t, h, 0)
	stream, err := client.Get(address + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	h.mu.Lock()
	tunnels := len(h.tunnels)
	h.mu.Unlock()
	if tunnels != 1 || h.client.ConnsCount() != 1 || h.slots.InUse() != 2 {
		t.Fatal("tunnel and overflow did not share the ceiling")
	}
	blocked, err := client.Get(address + "/blocked")
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != 503 {
		t.Fatal("tunnel bypassed the burst ceiling")
	}
	once.Do(func() { close(hold) })
	io.Copy(io.Discard, stream.Body)
	stream.Body.Close()
	waitConnections(t, h, 0)
}
