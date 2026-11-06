package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestStaleUpstreamConnectionRetry(t *testing.T) {
	for _, tt := range []struct {
		name, method, body string
		wantStatus         int
	}{
		{"get", "GET", "", 200},
		{"head", "HEAD", "", 200},
		{"post", "POST", "action", 502},
		{"put", "PUT", "action", 502},
		{"delete", "DELETE", "", 502},
		{"get with body", "GET", "action", 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			drop, dropped := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var calls atomic.Int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) != 1 {
					_, _ = io.Copy(io.Discard, r.Body)
					_, _ = io.WriteString(w, "ok")
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				_ = rw.Flush()
				<-drop
				_ = conn.Close()
				close(dropped)
			}))
			defer backend.Close()
			defer once.Do(func() { close(drop) })
			address, handler := frontend(t, testConfig(backend.URL))
			client := &http.Client{Timeout: 2 * time.Second}
			prime, err := client.Get(address)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, prime.Body)
			_ = prime.Body.Close()
			if err != nil || prime.StatusCode != 200 {
				t.Fatalf("initial response = %d, %v", prime.StatusCode, err)
			}
			once.Do(func() { close(drop) })
			select {
			case <-dropped:
			case <-time.After(time.Second):
				t.Fatal("backend did not close the pooled connection")
			}
			request, err := http.NewRequest(tt.method, address, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != tt.wantStatus {
				t.Fatalf("stale connection response = %d, %v; want %d", response.StatusCode, err, tt.wantStatus)
			}
			wantCalls := int64(1)
			if tt.wantStatus == 200 {
				wantCalls = 2
			}
			if calls.Load() != wantCalls {
				t.Fatalf("backend calls = %d; want %d", calls.Load(), wantCalls)
			}
			if handler.slots.InUse() != 0 {
				t.Error("completed request retained its admission slot")
			}
		})
	}
}

func TestUpstreamRetryIsBoundedAndDoesNotReplayOtherFailures(t *testing.T) {
	for _, tt := range []struct {
		name, method, body string
		err                error
		wantCalls, status  int
	}{
		{"closed get", "GET", "", io.EOF, 2, 502},
		{"closed head", "HEAD", "", io.EOF, 2, 502},
		{"closed sentinel", "GET", "", fasthttp.ErrConnectionClosed, 2, 502},
		{"reset get", "GET", "", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, 2, 502},
		{"broken pipe get", "GET", "", syscall.EPIPE, 2, 502},
		{"post", "POST", "action", io.EOF, 1, 502},
		{"put", "PUT", "action", io.EOF, 1, 502},
		{"patch", "PATCH", "action", io.EOF, 1, 502},
		{"delete", "DELETE", "", io.EOF, 1, 502},
		{"get with body", "GET", "action", io.EOF, 1, 502},
		{"timeout", "GET", "", fasthttp.ErrTimeout, 1, 504},
		{"headers", "GET", "", &fasthttp.ErrSmallBuffer{}, 1, 502},
		{"refused", "GET", "", syscall.ECONNREFUSED, 1, 502},
		{"tls", "GET", "", tls.RecordHeaderError{}, 1, 502},
		{"truncated", "GET", "", io.ErrUnexpectedEOF, 1, 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			address, handler := frontend(t, testConfig("http://127.0.0.1:8008"))
			transport := &upstreamFailureTransport{err: tt.err}
			handler.client.Transport = transport
			request, err := http.NewRequest(tt.method, address, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != tt.status || transport.calls.Load() != int64(tt.wantCalls) {
				t.Fatalf("status=%d calls=%d; want status=%d calls=%d", response.StatusCode, transport.calls.Load(), tt.status, tt.wantCalls)
			}
		})
	}
}

// Advertise transport errors as retryable so the public request path must apply
// the method/error policy and attempt bound, including for wrapped net errors.
type upstreamFailureTransport struct {
	err   error
	calls atomic.Int64
}

func (t *upstreamFailureTransport) RoundTrip(*fasthttp.HostClient, *fasthttp.Request, *fasthttp.Response) (bool, error) {
	t.calls.Add(1)
	return true, t.err
}

func TestUpstreamClosureDoesNotReplaySubmittedAction(t *testing.T) {
	for _, tt := range []struct {
		method, body string
		wantCalls    int64
	}{
		{"GET", "", 2},
		{"HEAD", "", 2},
		{"POST", "action", 1},
		{"PUT", "action", 1},
		{"PATCH", "action", 1},
	} {
		t.Run(tt.method, func(t *testing.T) {
			var calls atomic.Int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tt.body {
					t.Errorf("submitted body = %q, %v", body, err)
				}
				calls.Add(1)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
			}))
			defer backend.Close()
			address, _ := frontend(t, testConfig(backend.URL))
			request, err := http.NewRequest(tt.method, address, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != 502 || calls.Load() != tt.wantCalls {
				t.Fatalf("status=%d calls=%d; want status=502 calls=%d", response.StatusCode, calls.Load(), tt.wantCalls)
			}
		})
	}
}

func TestUpstreamHTTPErrorResponseDoesNotRetry(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "backend unavailable")
	}))
	defer backend.Close()
	address, _ := frontend(t, testConfig(backend.URL))
	response, err := (&http.Client{Timeout: time.Second}).Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 503 || string(body) != "backend unavailable" || calls.Load() != 1 {
		t.Fatalf("HTTP error response = %d %q %v, calls=%d", response.StatusCode, body, err, calls.Load())
	}
}

func TestUpstreamResponseHeaderBuffer(t *testing.T) {
	for _, tt := range []struct {
		name   string
		size   int
		status int
	}{
		{"large cookies", 8 << 10, 200},
		{"bounded headers", 40 << 10, 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cookie := "session=" + strings.Repeat("x", tt.size) + "; Path=/; HttpOnly"
			var calls atomic.Int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Set-Cookie", cookie)
				_, _ = io.WriteString(w, "ok")
			}))
			defer backend.Close()
			address, _ := frontend(t, testConfig(backend.URL))
			response, err := (&http.Client{Timeout: time.Second}).Get(address)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != tt.status || calls.Load() != 1 {
				t.Fatalf("large header response = %d %v, calls=%d", response.StatusCode, err, calls.Load())
			}
			if tt.status == 200 && (response.Header.Get("Set-Cookie") != cookie || string(body) != "ok") {
				t.Fatal("large response header or body changed during forwarding")
			}
		})
	}
}
