package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy-firewall/internal/admin"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"
)

func adminConfig(upstream string) config.Config {
	cfg := serverConfig(upstream)
	cfg.Admin.Enabled, cfg.Admin.User, cfg.Admin.Password, cfg.Admin.MaxHosts = true, "operator", "integration-test-password", 64
	return cfg
}

func startAdminTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	s := newServerForTest(t, cfg, true)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func readOverview(t *testing.T, s *Server) (monitoring.TotalsSnapshot, []monitoring.HostSnapshot) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, "http://"+s.HTTPAddress().String()+admin.BasePath+"/api/overview", nil)
	request.SetBasicAuth(s.cfg.Admin.User, s.cfg.Admin.Password)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("admin overview status = %d", response.StatusCode)
	}
	var overview struct {
		Totals monitoring.TotalsSnapshot `json:"totals"`
		Hosts  []monitoring.HostSnapshot `json:"hosts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&overview); err != nil {
		t.Fatal(err)
	}
	return overview.Totals, overview.Hosts
}

func waitForNoInFlight(t *testing.T, s *Server) {
	t.Helper()
	deadline, tick := time.NewTimer(time.Second), time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for s.stats.Totals().InFlight != 0 {
		select {
		case <-deadline.C:
			t.Fatal("monitoring retained a completed request")
		case <-tick.C:
		}
	}
}

func TestAdminAuthenticationAndPollingStayOutsideProxyRulesAndCounters(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "upstream") }))
	defer upstream.Close()
	s := startAdminTestServer(t, adminConfig(upstream.URL))
	request, _ := http.NewRequest(http.MethodGet, "http://"+s.HTTPAddress().String()+"/ordinary", nil)
	request.Host = "tenant.example"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	waitForNoInFlight(t, s)
	for _, path := range []string{admin.BasePath, admin.BasePath + "/assets/admin.js", admin.BasePath + "/api/overview", admin.BasePath + "/unknown", "/__PF/__ADMIN/api/overview", "/__pf/%5f_admin/api/overview"} {
		request, _ := http.NewRequest(http.MethodGet, "http://"+s.HTTPAddress().String()+path, nil)
		request.Header.Set("CF-Connecting-IP", "127.0.0.1")
		request.Header.Set("X-Forwarded-For", "127.0.0.1")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("unauthenticated admin path %q returned %d", path, response.StatusCode)
		}
	}
	for range 2 {
		totals, hosts := readOverview(t, s)
		if totals.Requests != 1 || totals.InFlight != 0 || len(hosts) != 1 || hosts[0].Hostname != "tenant.example" || hosts[0].BytesOut != 8 {
			t.Fatalf("admin polling affected proxy monitoring: totals=%+v hosts=%+v", totals, hosts)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("admin routes reached upstream: total calls = %d", calls.Load())
	}
}

func TestDisabledAdminSubtreeNeverReachesUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	s := newTestServer(t, serverConfig(upstream.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{admin.BasePath, admin.BasePath + "/api/unknown", "/__PF/__ADMIN/assets/admin.js", "/__pf/%5f_admin/api/overview"} {
		response, err := http.Get("http://" + s.HTTPAddress().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("disabled admin %q returned %d", path, response.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("disabled admin paths reached upstream %d times", calls.Load())
	}
}

func TestMonitoringRetainsInFlightThroughStreamAndUpgradeDenial(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "ordinary"
		if upgrade {
			name = "upgrade-denial"
		}
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if upgrade {
					w.WriteHeader(http.StatusForbidden)
				}
				_, _ = io.WriteString(w, "first\n")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, "last\n")
			}))
			defer upstream.Close()
			defer once.Do(func() { close(release) })
			s := startAdminTestServer(t, adminConfig(upstream.URL))
			request, _ := http.NewRequest(http.MethodGet, "http://"+s.HTTPAddress().String()+"/stream", nil)
			request.Host = "stream.example"
			if upgrade {
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
			}
			response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			reader := bufio.NewReader(response.Body)
			if first, err := reader.ReadString('\n'); err != nil || first != "first\n" {
				t.Fatalf("first chunk = %q, %v", first, err)
			}
			if totals, _ := readOverview(t, s); totals.Requests != 1 || totals.InFlight != 1 {
				t.Fatalf("active stream not tracked: %+v", totals)
			}
			once.Do(func() { close(release) })
			_, _ = io.Copy(io.Discard, reader)
			_ = response.Body.Close()
			waitForNoInFlight(t, s)
			_, hosts := readOverview(t, s)
			if len(hosts) != 1 || hosts[0].BytesOut != 11 || hosts[0].InFlight != 0 {
				t.Fatalf("completed stream counts = %+v", hosts)
			}
		})
	}
}

func TestMonitoringRetainsInFlightThroughUpgradedTunnel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\nready")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer upstream.Close()
	s := startAdminTestServer(t, adminConfig(upstream.URL))
	conn, err := net.Dial("tcp", s.HTTPAddress().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET /tunnel HTTP/1.1\r\nHost: socket.example\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("upgrade: %v, %v", response, err)
	}
	data := make([]byte, 5)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ready" {
		t.Fatalf("ready = %q, %v", data, err)
	}
	if totals, _ := readOverview(t, s); totals.Requests != 1 || totals.InFlight != 1 {
		t.Fatalf("active tunnel not tracked: %+v", totals)
	}
	_, _ = io.WriteString(conn, "ping")
	data = data[:4]
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ping" {
		t.Fatalf("echo = %q, %v", data, err)
	}
	_ = conn.Close()
	waitForNoInFlight(t, s)
	_, hosts := readOverview(t, s)
	if len(hosts) != 1 || hosts[0].Hostname != "socket.example" || hosts[0].BytesOut != 9 || hosts[0].InFlight != 0 {
		t.Fatalf("completed tunnel counts = %+v", hosts)
	}
}

func TestMonitoringCountsAdmission503WhileAdminRemainsAvailable(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	defer once.Do(func() { close(release) })
	cfg := adminConfig(upstream.URL)
	cfg.HTTP.MaxConcurrentRequests = 1
	s := startAdminTestServer(t, cfg)
	done := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + s.HTTPAddress().String() + "/ordinary")
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not start")
	}
	response, err := http.Get("http://" + s.HTTPAddress().String() + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("admission status = %d", response.StatusCode)
	}
	if totals, _ := readOverview(t, s); totals.Requests != 2 || totals.InFlight != 1 || totals.Errors5xx != 1 {
		t.Fatalf("admission monitoring = %+v", totals)
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitForNoInFlight(t, s)
}
