package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestHTTP2NegotiationFirewallForwardingAndStreams(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "last\n")
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s %s %s %s %s", r.Method, r.Host, r.RequestURI, r.Header.Get("X-Forwarded-Proto"), body)
	}))
	defer backend.Close()
	defer once.Do(func() { close(release) })
	cfg := serverConfig(backend.URL)
	cfg.HTTP.HTTP2Enable = true
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	base := "https://" + s.TLSAddress().String()
	stream, err := client.Get(base + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.ProtoMajor != 2 {
		t.Fatalf("negotiated %s", stream.Proto)
	}
	reader := bufio.NewReader(stream.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("stream did not flush: %q %v", line, err)
	}
	request, _ := http.NewRequest("POST", base+"/raw%2fPath//?q=%2f", strings.NewReader("body=value"))
	request.Host = "tenant.example"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.ProtoMajor != 2 || response.StatusCode != 200 || string(body) != "POST tenant.example /raw%2fPath//?q=%2f https body=value" {
		t.Fatalf("forwarded h2 response=%d %q %v", response.StatusCode, body, err)
	}
	bad, _ := http.NewRequest("GET", base+"/bad", strings.NewReader("forbidden"))
	response, err = client.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("HTTP/2 bypassed body policy: %d", response.StatusCode)
	}
	large, _ := http.NewRequest("POST", base+"/large", io.NopCloser(strings.NewReader(strings.Repeat("x", 2048))))
	response, err = client.Do(large)
	if err != nil {
		t.Fatal(err)
	}
	largeBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 413 {
		t.Fatalf("HTTP/2 bypassed streamed body limit: %d", response.StatusCode)
	}
	if !strings.Contains(string(largeBody), `<small>413</small>`) || !strings.Contains(string(largeBody), `id="status-language"`) || !strings.Contains(string(largeBody), "1 KiB") || response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("HTTP/2 lost the translated 413 page")
	}
	s.certGuard.mu.Lock()
	s.certGuard.blacklist["blocked.example"] = time.Now().Add(time.Hour)
	s.certGuard.mu.Unlock()
	blocked, _ := http.NewRequest("GET", base+"/", nil)
	blocked.Host = "blocked.example"
	response, err = client.Do(blocked)
	if err != nil {
		t.Fatal(err)
	}
	blockedBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 409 || !strings.Contains(string(blockedBody), "Hostname blacklisted") {
		t.Fatal("HTTP/2 lost blacklist status page")
	}
	once.Do(func() { close(release) })
	if rest, err := io.ReadAll(reader); err != nil || string(rest) != "last\n" {
		t.Fatalf("stream tail=%q %v", rest, err)
	}
}

func TestHTTP2GracefulShutdownClosesIdleConnection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	cfg := serverConfig(backend.URL)
	cfg.HTTP.HTTP2Enable = true
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + s.TLSAddress().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal("HTTP/2 prevented graceful shutdown", err)
	}
	s.mu.Lock()
	remaining := len(s.h2Conns)
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatal("HTTP/2 connections remained after shutdown")
	}
}
