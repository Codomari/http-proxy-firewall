package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/observability"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

// HTTP upgrade handshakes use a dedicated bounded tunnel. fasthttp's HTTP client
// intentionally does not expose upgraded connections from its keepalive pool.
func (h *Handler) upgrade(c fiber.Ctx, request *fasthttp.Request, protocol string, release func()) error {
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	dialer := &net.Dialer{Timeout: h.timeout}
	conn, err := dialer.Dial("tcp", h.client.Addr)
	if err != nil {
		return h.fail(c, err)
	}
	if h.client.IsTLS {
		tlsconn := tls.Client(conn, h.client.TLSConfig.Clone())
		if h.timeout > 0 {
			_ = tlsconn.SetDeadline(time.Now().Add(h.timeout))
		}
		if err := tlsconn.Handshake(); err != nil {
			_ = conn.Close()
			return h.fail(c, err)
		}
		conn = tlsconn
	}
	if h.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(h.timeout))
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", protocol)
	if _, err = request.WriteTo(conn); err != nil {
		_ = conn.Close()
		return h.fail(c, err)
	}
	if h.client.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(h.client.ReadTimeout))
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: string(request.Header.Method())})
	if err != nil {
		_ = conn.Close()
		return h.fail(c, err)
	}
	if response.StatusCode == http.StatusSwitchingProtocols && (!strings.EqualFold(response.Header.Get("Upgrade"), protocol) || !hasToken(response.Header.Get("Connection"), "upgrade")) {
		_ = response.Body.Close()
		_ = conn.Close()
		return h.fail(c, errors.New("upstream switched to an unexpected protocol"))
	}
	for name, values := range response.Header {
		for _, value := range values {
			c.Response().Header.Add(name, value)
		}
	}
	stripResponseHopHeaders(&c.Response().Header)
	if !h.track(conn) {
		_ = conn.Close()
		_ = response.Body.Close()
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		c.Status(response.StatusCode)
		size := int(response.ContentLength)
		if response.ContentLength < 0 || int64(size) != response.ContentLength {
			size = -1
		}
		stream := &upgradeResponseStream{ReadCloser: response.Body, close: func() { _ = conn.Close(); h.untrack(conn); release() }}
		c.Response().SetBodyStream(observability.WrapResponseStream(c, monitoring.WrapStream(c, stream, response.StatusCode)), size)
		c.Response().ImmediateHeaderFlush = true
		transferred = true
		return nil
	}
	c.Status(fiber.StatusSwitchingProtocols)
	c.Set("Connection", "Upgrade")
	c.Set("Upgrade", protocol)
	_ = conn.SetDeadline(time.Time{})
	// fasthttp normally writes the 101 before invoking Hijack. If that write
	// fails, its callback never runs. Own the handshake write inside the callback
	// so a disconnected client still releases the tunnel and monitoring state.
	header := append([]byte(nil), c.Response().Header.Header()...)
	complete := monitoring.Completion(c)
	finish := func(bytesOut uint64) {
		_ = conn.Close()
		h.untrack(conn)
		release()
		complete(fiber.StatusSwitchingProtocols, bytesOut)
	}
	frontend := c.RequestCtx().Conn()
	h.handoffs.register(frontend, func() { finish(0) })
	transferred = true
	c.RequestCtx().HijackSetNoResponse(true)
	c.RequestCtx().Hijack(func(client net.Conn) {
		if _, owned := h.handoffs.take(frontend); !owned {
			_ = client.Close()
			return
		}
		var bytesOut int64
		defer func() {
			_ = client.Close()
			finish(uint64(bytesOut))
		}()
		if n, err := client.Write(header); err != nil || n != len(header) {
			return
		}
		// The buffered reader preserves bytes the upstream sent with its 101.
		done := make(chan struct{}, 1)
		go func() { _, _ = io.Copy(conn, client); _ = conn.Close(); done <- struct{}{} }()
		bytesOut, _ = io.Copy(client, reader)
		_ = client.Close()
		_ = conn.Close()
		<-done
	})
	return nil
}

func (h *Handler) track(conn net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() {
		return false
	}
	h.tunnels[conn] = struct{}{}
	return true
}

func (h *Handler) untrack(conn net.Conn) { h.mu.Lock(); delete(h.tunnels, conn); h.mu.Unlock() }

type upgradeResponseStream struct {
	io.ReadCloser
	close func()
	once  sync.Once
}

func (s *upgradeResponseStream) Close() error {
	var err error
	s.once.Do(func() { s.close(); err = s.ReadCloser.Close() })
	return err
}
