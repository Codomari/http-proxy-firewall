package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"testing"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func TestUpstreamFailureLogsVerifiedClientIP(t *testing.T) {
	for _, tt := range []struct {
		name, peer, forwarded, cloudflare, want string
		trusted                                 []string
		trustCloudflare                         bool
	}{
		{"direct spoof", "198.51.100.1", "203.0.113.99", "203.0.113.99", "198.51.100.1", nil, true},
		{"trusted chain", "10.0.0.2", "203.0.113.99, 198.51.100.3, 10.0.0.4", "", "198.51.100.3", []string{"10.0.0.0/8"}, false},
		{"trusted cloudflare", "10.0.0.2", "", "2001:db8::1", "2001:db8::1", []string{"10.0.0.0/8"}, true},
		{"invalid forwarded", "10.0.0.2", "invalid", "", "10.0.0.2", []string{"10.0.0.0/8"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&output, nil))
			cfg := config.Defaults()
			cfg.Proxy.IPv4Redirect = ""
			cfg.Firewall.TrustedProxies = tt.trusted
			cfg.Firewall.TrustCloudflareHeader = tt.trustCloudflare
			engine, err := firewall.New(cfg, nil, nil, logger)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := New(cfg, logger)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			handler.client.Dial = func(string) (net.Conn, error) {
				return nil, errors.New("private upstream error must not be logged")
			}
			app := fiber.New()
			app.Use(engine.Handler)
			app.Use(handler.Handle)
			serve := app.Handler()
			for range 2 {
				ctx := new(fasthttp.RequestCtx)
				ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP(tt.peer), Port: 1234}, nil)
				ctx.Request.Header.SetMethod("GET")
				ctx.Request.SetRequestURI("/asset.css")
				ctx.Request.Header.SetHost("example.test")
				ctx.Request.Header.Set("X-Forwarded-For", tt.forwarded)
				ctx.Request.Header.Set("CF-Connecting-IP", tt.cloudflare)
				serve(ctx)
				if ctx.Response.StatusCode() != 502 {
					t.Fatalf("failure status = %d", ctx.Response.StatusCode())
				}
			}
			line := output.String()
			if strings.Count(line, "\n") != 1 || !strings.Contains(line, `msg="upstream request failed"`) || !strings.Contains(line, "client_ip="+tt.want+" ") || !strings.Contains(line, "error_type=*errors.errorString") || !strings.Contains(line, "hostname=example.test") {
				t.Fatalf("missing verified IP or lost error sampling: %q", line)
			}
			for _, field := range []string{"status=502", "upstream=127.0.0.1:8008", "method=GET", "error_reason=upstream_error"} {
				if !strings.Contains(line, field) {
					t.Errorf("missing %q in warning: %q", field, line)
				}
			}
			if strings.Contains(line, "private upstream") || strings.Contains(line, "203.0.113.99") {
				t.Fatalf("warning exposed raw error text or spoofed identity: %q", line)
			}
		})
	}
}

func TestUpstreamFailureLogsReasonAndReturnedStatus(t *testing.T) {
	for _, tt := range []struct {
		name, reason string
		err          error
		status       int
	}{
		{"closed", "connection_closed", fasthttp.ErrConnectionClosed, 502},
		{"eof", "connection_closed", fmt.Errorf("private error: %w", io.EOF), 502},
		{"reset", "connection_reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, 502},
		{"pipe", "broken_pipe", fmt.Errorf("private error: %w", syscall.EPIPE), 502},
		{"refused", "connection_refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, 502},
		{"unreachable", "network_unreachable", syscall.ENETUNREACH, 502},
		{"dns", "dns_error", &net.DNSError{Err: "private error", Name: "private.internal"}, 502},
		{"headers", "response_headers_too_large", &fasthttp.ErrSmallBuffer{}, 502},
		{"certificate", "tls_certificate_error", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, 502},
		{"tls", "tls_error", tls.RecordHeaderError{Msg: "private error"}, 502},
		{"tls alert", "tls_error", tls.AlertError(40), 502},
		{"truncated", "unexpected_eof", io.ErrUnexpectedEOF, 502},
		{"upgrade", "invalid_upgrade_response", errUnexpectedUpgradeProtocol, 502},
		{"pool", "pool_exhausted", fasthttp.ErrNoFreeConns, 503},
		{"timeout", "timeout", fasthttp.ErrTimeout, 504},
		{"dns timeout", "timeout", &net.DNSError{Err: "private error", IsTimeout: true}, 504},
		{"unknown", "upstream_error", errors.New("private error"), 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			handler, err := New(testConfig("http://127.0.0.1:8008"), slog.New(slog.NewTextHandler(&output, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error { return handler.fail(c, tt.err) })
			ctx := new(fasthttp.RequestCtx)
			ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1234}, nil)
			ctx.Request.Header.SetMethod("POST")
			ctx.Request.SetRequestURI("/private-path?secret=private-query")
			ctx.Request.Header.SetHost("example.test")
			ctx.Request.Header.Set("Authorization", "private-authorization")
			ctx.Request.Header.Set("Cookie", "session=private-cookie")
			ctx.Request.SetBodyString("private-body")
			app.Handler()(ctx)
			if ctx.Response.StatusCode() != tt.status {
				t.Fatalf("response status = %d; want %d", ctx.Response.StatusCode(), tt.status)
			}
			if tt.status == 503 && string(ctx.Response.Header.Peek("Retry-After")) != "1" {
				t.Fatal("pool exhaustion lost Retry-After")
			}
			line := output.String()
			for _, field := range []string{
				"error_reason=" + tt.reason, fmt.Sprintf("status=%d", tt.status),
				"upstream=127.0.0.1:8008", "method=POST", "hostname=example.test",
			} {
				if !strings.Contains(line, field) {
					t.Errorf("missing %q in warning: %q", field, line)
				}
			}
			if strings.Contains(line, "private") || strings.Count(line, "\n") != 1 {
				t.Fatalf("warning leaked private data or extra lines: %q", line)
			}
		})
	}
}
