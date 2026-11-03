package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDebugCapturesRequestsBeforeAdmissionAndFirewall(t *testing.T) {
	t.Chdir(t.TempDir())
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(started)
			<-release
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	defer once.Do(func() { close(release) })
	cfg := adminConfig(upstream.URL)
	cfg.Admin.URI = "ops"
	cfg.HTTP.MaxConcurrentRequests = 1
	cfg.Firewall.TrustedProxies = []string{"127.0.0.0/8"}
	s := startAdminTestServer(t, cfg)
	address := "http://" + s.HTTPAddress().String()
	client := &http.Client{Timeout: 2 * time.Second}
	control := func(method, hostname string) {
		t.Helper()
		req, _ := http.NewRequest(method, address+"/ops/api/debug?hostname="+url.QueryEscape(hostname), nil)
		req.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
		req.Header.Set("X-PF-Admin", "1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("debug control status=%d", resp.StatusCode)
		}
	}
	control("POST", "*.example.com")
	send := func(host, path, body string) {
		t.Helper()
		method := "GET"
		if body != "" {
			method = "POST"
		}
		req, _ := http.NewRequest(method, address+path, strings.NewReader(body))
		req.Host = host
		req.Header.Set("X-Forwarded-For", "203.0.113.42")
		req.Header.Set("X-Debug-Test", "original-header")
		if body != "" {
			req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 204
		if body != "" {
			want = 400
		}
		if resp.StatusCode != want {
			t.Fatalf("request status=%d want=%d", resp.StatusCode, want)
		}
	}
	send("WWW.Example.com:80", "/MiXeD%2fPath//?q=%2f&x=+", "")
	send("a.b.example.com", "/blocked", "invalid multipart")
	send("example.com", "/bare-excluded", "")
	send("example.com.evil", "/suffix-excluded", "")
	// An extension method must reach capture under its original wire spelling.
	conn, err := net.Dial("tcp", s.HTTPAddress().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn, "CUSTOM /extension HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != 204 {
		t.Fatalf("extension response: %v", err)
	}
	response.Body.Close()
	conn.Close()
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", address+"/hold", nil)
		req.Host = "api.example.com"
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream did not start")
	}
	req, _ := http.NewRequest("GET", address+"/admission", nil)
	req.Host = "api.example.com"
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 503 {
		t.Fatalf("admission: %v", err)
	}
	resp.Body.Close()
	// Controls remain accessible while the only request slot is occupied.
	control("DELETE", "")
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	send("api.example.com", "/after-disable", "")
	req, _ = http.NewRequest("GET", address+"/ops/api/debug/logs", nil)
	req.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Lines  []string `json:"lines"`
		Status struct {
			Enabled bool   `json:"enabled"`
			File    string `json:"file"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(result.Lines, "\n")
	if resp.StatusCode != 200 || len(result.Lines) != 5 || result.Status.Enabled {
		t.Fatalf("capture status=%d lines=%d enabled=%v entries=%q", resp.StatusCode, len(result.Lines), result.Status.Enabled, result.Lines)
	}
	for _, want := range []string{"FROM: 203.0.113.42, TO: www.example.com, GET /MiXeD%2fPath//?q=%2f&x=+", "original-header", "POST /blocked", "CUSTOM /extension", "GET /hold", "GET /admission"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing captured metadata %q", want)
		}
	}
	for _, excluded := range []string{"/bare-excluded", "/suffix-excluded", "/after-disable", "/ops/api"} {
		if strings.Contains(all, excluded) {
			t.Fatalf("unwanted capture %q", excluded)
		}
	}
	file, err := os.Open(result.Status.File)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	if string(data) != all+"\n" {
		t.Fatal("admin view does not match file contents")
	}
}

func TestCloudflareHostnameSwitchUpdatesDebugFilterAndUpstreamIP(t *testing.T) {
	t.Chdir(t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	}))
	defer upstream.Close()
	cfg := adminConfig(upstream.URL)
	cfg.Firewall.TrustedProxies = []string{"127.0.0.0/8"}
	s := startAdminTestServer(t, cfg)
	address := "http://" + s.HTTPAddress().String()
	client := &http.Client{Timeout: 2 * time.Second}
	api := func(method, path string) []byte {
		t.Helper()
		req, _ := http.NewRequest(method, address+"/__pf/__admin/api/"+path, nil)
		req.SetBasicAuth(cfg.Admin.Accounts[0].User, cfg.Admin.Accounts[0].Password)
		req.Header.Set("X-PF-Admin", "1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("API status=%d: %s", resp.StatusCode, body)
		}
		return body
	}
	send := func(host, ip, want string) {
		t.Helper()
		req, _ := http.NewRequest("GET", address+"/traffic", nil)
		req.Host = host
		req.Header.Set("CF-Connecting-IP", ip)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != want {
			t.Fatalf("upstream client IP=%q want=%q status=%d", body, want, resp.StatusCode)
		}
	}
	api("POST", "debug?hostname=api.example.com&client_ip=203.0.113.8")
	send("api.example.com", "203.0.113.8", "127.0.0.1")
	api("POST", "cloudflare-hosts?hostname=api.example.com&enabled=true")
	send("api.example.com", "203.0.113.8", "203.0.113.8")
	send("api.example.com", "203.0.113.9", "203.0.113.9")
	send("other.example.com", "203.0.113.8", "127.0.0.1")
	api("POST", "cloudflare-hosts?hostname=api.example.com&enabled=false")
	send("api.example.com", "203.0.113.8", "127.0.0.1")
	var result struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(api("GET", "debug/logs"), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Lines) != 1 || !strings.Contains(result.Lines[0], "FROM: 203.0.113.8, TO: api.example.com") {
		t.Fatalf("debug did not filter by resolved Cloudflare source: %q", result.Lines)
	}
	// Host trust remains operational independently of an active debug capture.
	api("DELETE", "debug")
	api("POST", "cloudflare-hosts?hostname=api.example.com&enabled=true")
	send("api.example.com", "203.0.113.8", "203.0.113.8")
}
