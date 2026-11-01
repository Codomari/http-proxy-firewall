package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingListener struct {
	net.Listener
	writes *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, writes: l.writes}, nil
}

type countingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func TestSmallFixedResponseCombinesHeadersAndBodyInOneWrite(t *testing.T) {
	body := strings.Repeat("x", 1024)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()
	var writes atomic.Int64
	address, _ := frontendWithListener(t, testConfig(upstream.URL), func(listener net.Listener) net.Listener {
		return &countingListener{Listener: listener, writes: &writes}
	})
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(address)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(got) != body || response.ContentLength != int64(len(body)) {
		t.Fatalf("response = %d bytes, content-length %d, error %v", len(got), response.ContentLength, err)
	}
	if count := writes.Load(); count != 1 {
		t.Errorf("small fixed response used %d connection writes; want headers and body combined into one", count)
	}
}

func TestFixedLengthEventStreamFlushesHeadersBeforeBody(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Text/Event-Stream; charset=utf-8")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "event")
	}))
	defer upstream.Close()
	defer once.Do(func() { close(release) })
	address, _ := frontend(t, testConfig(upstream.URL))
	response, err := (&http.Client{Timeout: time.Second}).Get(address)
	if err != nil {
		t.Fatalf("SSE headers were delayed while the upstream held its body: %v", err)
	}
	defer response.Body.Close()
	once.Do(func() { close(release) })
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "event" {
		t.Fatalf("event body = %q, %v", body, err)
	}
}
