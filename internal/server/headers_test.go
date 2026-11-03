package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	buildinfo "http-proxy-firewall"

	"http-proxy-firewall/internal/config"
)

func TestServerHeaderForProxyAdminAndRejections(t *testing.T) {
	if config.ServerName != "codomari/proxy-firewall/"+buildinfo.Version {
		t.Fatal("Server header does not include the embedded version")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server", "nginx")
		w.Header().Add("Server", "another-upstream")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cfg := serverConfig(upstream.URL)
	cfg.Admin = config.Admin{Enabled: true, Accounts: []config.AdminAccount{{User: "operator", Password: "test-password"}}, MaxHosts: 10}
	cfg.Observability.Metrics = true
	s := newServerForTest(t, cfg, true)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, tt := range []struct {
		path, body    string
		authenticated bool
		status        int
	}{
		{"/asset.css", "", false, 200},
		{"/__pf/__admin", "", false, 401},
		{"/__pf/__admin", "", true, 200},
		{"/__pf/__admin/api/overview", "", true, 200},
		{"/__pf/__admin/assets/admin.js", "", true, 200},
		{"/__system__/__metrics__", "", false, 200},
		{"/invalid", "unexpected GET body", false, 400},
	} {
		req, err := http.NewRequest(http.MethodGet, "http://"+s.HTTPAddress().String()+tt.path, strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "tenant.example"
		if tt.authenticated {
			req.SetBasicAuth("operator", "test-password")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tt.status || len(resp.Header.Values("Server")) != 1 || resp.Header.Get("Server") != config.ServerName {
			t.Fatalf("%s: status=%d server=%v", tt.path, resp.StatusCode, resp.Header.Values("Server"))
		}
	}
	conn, err := net.Dial("tcp", s.HTTPAddress().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: tenant.example\r\nContent-Length: invalid\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Server") != config.ServerName {
		t.Fatalf("parser error response: status=%d server=%q", resp.StatusCode, resp.Header.Get("Server"))
	}
}
