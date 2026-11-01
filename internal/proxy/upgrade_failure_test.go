package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/monitoring"
)

type failedUpgradeListener struct {
	net.Listener
	mode          string
	pipelineBytes int
}

func (l *failedUpgradeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &failedUpgradeConn{Conn: conn, mode: l.mode, pipelineBytes: l.pipelineBytes}, nil
}

type failedUpgradeConn struct {
	net.Conn
	mode          string
	pipelineBytes int
}

func (c *failedUpgradeConn) Read(p []byte) (int, error) {
	if c.pipelineBytes > 0 {
		// Keep both pipelined requests in the first native read so the first
		// response remains buffered when the upgrade is ready for handoff.
		size := c.pipelineBytes
		c.pipelineBytes = 0
		if size > len(p) {
			return 0, io.ErrShortBuffer
		}
		return io.ReadFull(c.Conn, p[:size])
	}
	return c.Conn.Read(p)
}

func (c *failedUpgradeConn) Write(p []byte) (int, error) {
	fail := c.mode == "101-write" && bytes.HasPrefix(p, []byte("HTTP/1.1 101"))
	fail = fail || (c.mode == "pipeline-flush" && bytes.HasPrefix(p, []byte("HTTP/1.1 200")))
	if fail {
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func (c *failedUpgradeConn) SetDeadline(deadline time.Time) error {
	if c.mode == "deadline-reset" && deadline.IsZero() {
		_ = c.Conn.Close()
		return io.ErrClosedPipe
	}
	return c.Conn.SetDeadline(deadline)
}

func TestAbortedUpgradeReleasesTunnelAndMonitoring(t *testing.T) {
	for _, mode := range []string{"101-write", "deadline-reset", "pipeline-flush"} {
		t.Run(mode, func(t *testing.T) {
			upstreamClosed := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ordinary" {
					_, _ = io.WriteString(w, "ok")
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				defer close(upstreamClosed)
				_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				_ = rw.Flush()
				_, _ = io.Copy(io.Discard, rw)
			}))
			defer upstream.Close()
			cfg := testConfig(upstream.URL)
			cfg.Admin.Enabled, cfg.Admin.MaxHosts, cfg.Proxy.MaxConnections = true, 64, 1
			cfg.Proxy.Routes = map[string]string{"route.example": upstream.URL}
			stats := monitoring.New(cfg)
			pipeline := "GET /ordinary HTTP/1.1\r\nHost: route.example\r\n\r\nGET /socket HTTP/1.1\r\nHost: route.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
			address, handler := frontendWithListener(t, cfg, func(listener net.Listener) net.Listener {
				length := 0
				if mode == "pipeline-flush" {
					length = len(pipeline)
				}
				return &failedUpgradeListener{Listener: listener, mode: mode, pipelineBytes: length}
			}, stats.Middleware(firewall.CanonicalHostname))
			if mode == "pipeline-flush" {
				client, err := net.Dial("tcp", strings.TrimPrefix(address, "http://"))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(time.Second))
				_, _ = io.WriteString(client, pipeline)
				_, _ = io.Copy(io.Discard, client)
			} else {
				request, _ := http.NewRequest(http.MethodGet, address+"/socket", nil)
				request.Host = "route.example"
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
				response, err := (&http.Client{Timeout: time.Second}).Do(request)
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("expected the frontend handshake to fail")
				}
			}
			select {
			case <-upstreamClosed:
			case <-time.After(time.Second):
				t.Fatal("upstream tunnel leaked after failed frontend handshake")
			}
			route := handler.routes["route.example"]
			deadline, tick := time.NewTimer(time.Second), time.NewTicker(time.Millisecond)
			defer deadline.Stop()
			defer tick.Stop()
			for len(route.slots) != 0 || stats.Totals().InFlight != 0 || handler.handoffs.count.Load() != 0 {
				select {
				case <-deadline.C:
					t.Fatal("aborted upgrade retained admission, pending handoff, or monitoring state")
				case <-tick.C:
				}
			}
			route.mu.Lock()
			tunnels := len(route.tunnels)
			route.mu.Unlock()
			if tunnels != 0 {
				t.Errorf("failed upgrade retained %d tracked tunnels", tunnels)
			}
			want := uint64(1)
			if mode == "pipeline-flush" {
				want = 2
			}
			if totals := stats.Totals(); totals.Requests != want {
				t.Errorf("request monitoring = %+v", totals)
			}
		})
	}
}
