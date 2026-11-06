package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestRetrySettingsApplyImmediatelyToEveryRoute(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:8008")
	cfg.Proxy.Routes = map[string]string{"other.example": "http://127.0.0.1:8009"}
	h, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, handler := range []*Handler{h, h.routes["other.example"]} {
		handler.client.Transport = &upstreamFailureTransport{err: fasthttp.ErrConnectionClosed}
	}
	for _, retries := range []int{5, 3, 0} {
		h.SetRequestRetryTimes(retries)
		for name, handler := range map[string]*Handler{"default": h, "route": h.routes["other.example"]} {
			transport := handler.client.Transport.(*upstreamFailureTransport)
			before := transport.calls.Load()
			request, response := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
			request.SetRequestURI("http://example.test/")
			err := handler.doRequest(request, response)
			fasthttp.ReleaseRequest(request)
			fasthttp.ReleaseResponse(response)
			if err == nil || transport.calls.Load()-before != int64(retries+1) {
				t.Fatalf("%s retries=%d: calls=%d err=%v", name, retries, transport.calls.Load()-before, err)
			}
		}
	}
}

func TestRetryDiscardsOtherStaleConnections(t *testing.T) {
	drop, dropped := make(chan struct{}), make(chan struct{}, 2)
	var release sync.Once
	var calls atomic.Int64
	allPrimed := make(chan struct{})
	var primed atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 2 {
			_, _ = io.WriteString(w, "fresh")
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		// Keep both requests in flight so the upstream pool opens two connections.
		if primed.Add(1) == 2 {
			close(allPrimed)
		}
		select {
		case <-allPrimed:
		case <-drop:
			return
		case <-time.After(2 * time.Second):
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		_ = rw.Flush()
		<-drop
		_ = conn.Close()
		dropped <- struct{}{}
	}))
	defer backend.Close()
	defer release.Do(func() { close(drop) })
	address, _ := frontend(t, testConfig(backend.URL))
	client := &http.Client{Timeout: 2 * time.Second}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			response, err := client.Get(address)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != 200 {
					err = fmt.Errorf("prime status=%d", response.StatusCode)
				}
			}
			done <- err
		}()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	release.Do(func() { close(drop) })
	for range 2 {
		select {
		case <-dropped:
		case <-time.After(time.Second):
			t.Fatal("stale connections were not closed")
		}
	}
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || string(body) != "fresh" || calls.Load() != 3 {
		t.Fatalf("retry did not open a healthy connection: status=%d body=%s calls=%d", response.StatusCode, body, calls.Load())
	}
}
