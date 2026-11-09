package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTP2CleartextUpgradeFallsBackToHTTP1(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.Header.Get("Upgrade") != "" || r.Header.Get("HTTP2-Settings") != "" {
			t.Error("h2c upgrade reached the origin")
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	address, _ := frontend(t, testConfig(backend.URL))
	request, _ := http.NewRequest("GET", address+"/", nil)
	request.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	request.Header.Set("Upgrade", "h2c")
	request.Header.Set("HTTP2-Settings", "AAMAAABkAAQAAP__")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("h2c request did not fall back to ordinary HTTP: %d", response.StatusCode)
	}
}

func TestVirtualHostRoutesAndDefaultFallback(t *testing.T) {
	upstream := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, name+" "+r.Host) }))
	}
	defaultServer, first, second := upstream("default"), upstream("first"), upstream("second")
	defer defaultServer.Close()
	defer first.Close()
	defer second.Close()
	cfg := testConfig(defaultServer.URL)
	cfg.Proxy.Routes = map[string]string{"one.example": first.URL, "TWO.EXAMPLE.": second.URL}
	address, handler := frontend(t, cfg)
	// Changes to caller-owned configuration cannot change the routing table.
	cfg.Proxy.Routes["one.example"] = defaultServer.URL
	for _, tt := range []struct{ host, want string }{{"ONE.Example:8080", "first"}, {"two.example.", "second"}, {"other.example", "default"}} {
		request, err := http.NewRequest(http.MethodGet, address+"/raw%2fpath", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = tt.host
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != tt.want+" "+tt.host {
			t.Errorf("host %q returned %q, %v", tt.host, body, err)
		}
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	for name, route := range handler.routes {
		if !route.closed.Load() {
			t.Errorf("route %q was not closed", name)
		}
	}
}

func TestUpgradeDenialPreservesStatusAndBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Reason", "denied")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "access denied")
	}))
	defer upstream.Close()
	address, _ := frontend(t, testConfig(upstream.URL))
	request, _ := http.NewRequest(http.MethodGet, address+"/socket", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusForbidden || string(body) != "access denied" || response.Header.Get("X-Reason") != "denied" {
		t.Fatalf("denial response = %d %q %v", response.StatusCode, body, err)
	}
}
