package server

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRestartScreenIsEmbeddedAndOnlyUsedDuringFirewallShutdown(t *testing.T) {
	t.Chdir(t.TempDir())
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
		io.WriteString(w, "backend unavailable")
	}))
	defer upstream.Close()
	cfg := serverConfig(upstream.URL)
	certFile, keyFile, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, certFile, keyFile
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport}
	address := "http://" + s.HTTPAddress().String()
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 503 || !strings.Contains(string(body), `data-page="service-unavailable"`) || strings.Contains(string(body), `data-page="restart"`) {
		t.Fatal("backend errors were mistaken for firewall restarts")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(ctx) }()
	deadline := time.Now().Add(time.Second)
	for !s.restarting.Load() {
		if time.Now().After(deadline) {
			t.Fatal("shutdown never announced restart")
		}
		time.Sleep(time.Millisecond)
	}
	for _, endpoint := range []string{address, "https://" + s.TLSAddress().String()} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			request, _ := http.NewRequest(method, endpoint+"/anything?token=must-not-be-reflected", nil)
			request.Host = "tenant.example.test"
			response, err = client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 540 || response.Status != "540 Server Restarting" || response.Header.Get("Retry-After") != "" || response.Header.Get("Cache-Control") != "no-store" || !response.Close {
				t.Fatalf("restart response: %s %v", response.Status, response.Header)
			}
			if method == "HEAD" {
				if len(body) != 0 {
					t.Fatal("HEAD response sent a body")
				}
				continue
			}
			for _, want := range []string{"Server restarting", "request-animation", restartingJS, restartingCSS} {
				if !strings.Contains(string(body), want) {
					t.Fatal("embedded restart page missing content")
				}
			}
			for _, excluded := range []string{"{{STYLE}}", "{{SCRIPT}}", "must-not-be-reflected", "<script src=", "<link ", "countdown", "Retrying in 3"} {
				if strings.Contains(string(body), excluded) {
					t.Fatalf("page contains external resource or unexpanded text: %s", excluded)
				}
			}
			csp := response.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, assetHash(restartingJS)) || !strings.Contains(csp, assetHash(restartingCSS)) {
				t.Fatal("CSP does not allow the embedded assets")
			}
		}
	}
	if calls.Load() != 1 {
		t.Fatal("requests reached the backend during restart")
	}
	if entries, err := os.ReadDir("."); err != nil || len(entries) != 0 {
		t.Fatal("restart page needed runtime files")
	}
	if err := <-stopped; err != nil {
		t.Fatalf("stop: %v", err)
	}
}
