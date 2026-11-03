package server

import (
	"context"
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
	s := newTestServer(t, serverConfig(upstream.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	address := "http://" + s.HTTPAddress().String()
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 503 || string(body) != "backend unavailable" {
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
	for _, method := range []string{"GET", "HEAD", "POST"} {
		request, _ := http.NewRequest(method, address+"/anything?token=must-not-be-reflected", nil)
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 540 || response.Status != "540 Server Restarting" || response.Header.Get("Retry-After") != "3" || response.Header.Get("Cache-Control") != "no-store" || !response.Close {
			t.Fatalf("restart response: %s %v", response.Status, response.Header)
		}
		if method == "HEAD" {
			if len(body) != 0 {
				t.Fatal("HEAD response sent a body")
			}
			continue
		}
		for _, want := range []string{"Server restarting", restartingJS, restartingCSS} {
			if !strings.Contains(string(body), want) {
				t.Fatal("embedded restart page missing content")
			}
		}
		for _, excluded := range []string{"{{STYLE}}", "{{SCRIPT}}", "must-not-be-reflected", "<script src=", "<link "} {
			if strings.Contains(string(body), excluded) {
				t.Fatalf("page contains external resource or unexpanded text: %s", excluded)
			}
		}
		csp := response.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, assetHash(restartingJS)) || !strings.Contains(csp, assetHash(restartingCSS)) {
			t.Fatal("CSP does not allow the embedded assets")
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
