package proxy

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
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
			if strings.Count(line, "\n") != 1 || !strings.Contains(line, `msg="upstream request failed"`) || !strings.Contains(line, "client_ip="+tt.want+" ") || !strings.Contains(line, "error_type=*errors.errorString") {
				t.Fatalf("missing verified IP or lost error sampling: %q", line)
			}
			if strings.Contains(line, "private upstream") || strings.Contains(line, "203.0.113.99") {
				t.Fatalf("warning exposed raw error text or spoofed identity: %q", line)
			}
		})
	}
}
