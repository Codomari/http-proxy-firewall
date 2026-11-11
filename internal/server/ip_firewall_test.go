package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestIPFirewall444BeforeStaticAdminAndBodyRules(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer upstream.Close()
	cfg := adminConfig(upstream.URL)
	cfg.Firewall.TrustedProxies = []string{"127.0.0.1/32"}
	cfg.Firewall.IPFirewallNetworks = []string{"198.51.100.0/24", "2001:db8::/32"}
	cfg.Firewall.WhitelistIPs = []string{"198.51.100.8"}
	s := startAdminTestServer(t, cfg)
	for _, tc := range []struct{ ip, target, headers string }{
		{"198.51.100.9", "/style.css", ""},
		{"2001:db8::9", "/", ""},
		{"198.51.100.9", "/__pf/__admin", ""},
		// A bot query would normally receive a 403; the IP drop runs first.
		{"198.51.100.9", "/?password=secret", "User-Agent: Googlebot\r\n"},
	} {
		conn, err := net.DialTimeout("tcp", s.HTTPAddress().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: %s\r\n%s\r\n", tc.target, tc.ip, tc.headers)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal("missing 444 response", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 444 || len(body) != 0 || !response.Close || response.ContentLength != 0 {
			t.Fatalf("invalid rejection: status=%d body=%q close=%v length=%d error=%v", response.StatusCode, body, response.Close, response.ContentLength, err)
		}
		_, readErr := reader.ReadByte()
		_ = conn.Close()
		if readErr != io.EOF {
			t.Fatalf("444 connection did not close cleanly: %v", readErr)
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			t.Fatal("blacklisted connection stayed open")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("blacklisted traffic reached the upstream")
	}
	totals, hosts := readOverview(t, s)
	if totals.IPFirewallRejected != 4 || totals.Requests != 4 || totals.Rejected != 4 || totals.InFlight != 0 || len(hosts) != 1 || hosts[0].IPFirewallRejected != 4 || hosts[0].Requests != 4 || hosts[0].Rejected != 4 {
		t.Fatalf("early drops missing from monitoring: totals=%+v hosts=%+v", totals, hosts)
	}
	request, _ := http.NewRequest("GET", "http://"+s.HTTPAddress().String()+"/", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.8")
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal("whitelist did not win", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || calls.Load() != 1 {
		t.Fatal("whitelisted request was not forwarded")
	}
	// A permitted client still has to pass body inspection.
	bad, _ := http.NewRequest("POST", "http://"+s.HTTPAddress().String()+"/style.css", nil)
	bad.Header.Set("X-Forwarded-For", "198.51.100.8")
	bad.Header.Set("Content-Encoding", "gzip")
	response, err = (&http.Client{Timeout: time.Second}).Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 415 || calls.Load() != 1 {
		t.Fatal("whitelist skipped body validation")
	}
	totals, _ = readOverview(t, s)
	if totals.IPFirewallRejected != 4 || totals.Requests != 6 || totals.Rejected != 5 {
		t.Fatalf("non-IP rejections changed the IP Firewall counter: %+v", totals)
	}
}

func TestIPFirewallHTTP2Empty444AndGracefulConnectionClose(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "upstream") }))
	defer backend.Close()
	cfg := serverConfig(backend.URL)
	cfg.HTTP.HTTP2Enable = true
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	cfg.Firewall.TrustedProxies = []string{"127.0.0.1/32"}
	cfg.Firewall.IPFirewallNetworks = []string{"198.51.100.0/24"}
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest("GET", "https://"+s.TLSAddress().String()+"/style.css", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal("HTTP/2 lost the 444 response", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 444 || len(body) != 0 || calls.Load() != 0 || response.Header.Get("Connection") != "" {
		t.Fatalf("HTTP/2 rejection: status=%d body=%q error=%v calls=%d", response.StatusCode, body, err, calls.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		remaining := len(s.h2Conns)
		s.mu.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP/2 connection stayed open after 444")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIPFirewallRunsBeforeRestartResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("blocked request reached upstream") }))
	defer backend.Close()
	cfg := adminConfig(backend.URL)
	cfg.Firewall.TrustedProxies = []string{"127.0.0.1/32"}
	cfg.Firewall.IPFirewallNetworks = []string{"198.51.100.0/24"}
	s := startAdminTestServer(t, cfg)
	s.restarting.Store(true)
	request, _ := http.NewRequest("GET", "http://"+s.HTTPAddress().String()+"/", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal("missing 444 during restart", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 444 || len(body) != 0 || readErr != nil || s.stats.Totals().IPFirewallRejected != 1 {
		t.Fatalf("restart bypassed IP Firewall: response=%v error=%v totals=%+v", response, err, s.stats.Totals())
	}
}
