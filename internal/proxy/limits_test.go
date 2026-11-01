package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResponseStreamRetainsAdmissionSlotUntilTransferFinishes(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "last\n")
	}))
	defer upstream.Close()
	defer once.Do(func() { close(release) })
	cfg := testConfig(upstream.URL)
	cfg.Proxy.MaxConnections = 1
	address, handler := frontend(t, cfg)
	client := &http.Client{Timeout: 2 * time.Second}
	first, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	reader := bufio.NewReader(first.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("first chunk = %q, %v", line, err)
	}
	if len(handler.slots) != 1 {
		t.Fatal("stream released admission after response headers")
	}
	second, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Body.Close()
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second request status = %d", second.StatusCode)
	}
	once.Do(func() { close(release) })
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeSharesOrdinaryRequestAdmissionLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer upstream.Close()
	cfg := testConfig(upstream.URL)
	cfg.Proxy.MaxConnections = 1
	address, _ := frontend(t, cfg)
	conn, err := net.Dial("tcp", strings.TrimPrefix(address, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: private.v1\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 || response.Header.Get("Upgrade") != "private.v1" {
		t.Fatalf("generic upgrade = %d %v", response.StatusCode, response.Header)
	}
	ordinary, err := (&http.Client{Timeout: time.Second}).Get(address)
	if err != nil {
		t.Fatal(err)
	}
	_ = ordinary.Body.Close()
	if ordinary.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("ordinary request bypassed upgrade admission: %d", ordinary.StatusCode)
	}
}
