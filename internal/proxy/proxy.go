// Package proxy forwards inspected requests through immutable host routes and
// bounded, reusable upstream pools.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

type Handler struct {
	client    *fasthttp.HostClient
	target    *url.URL
	redirect  string
	logger    *slog.Logger
	timeout   time.Duration
	slots     chan struct{}
	mu        sync.Mutex
	tunnels   map[net.Conn]struct{}
	closed    atomic.Bool
	lastError time.Time
	routes    map[string]*Handler
	handoffs  *upgradeHandoffs
}

func New(cfg config.Config, logger *slog.Logger) (*Handler, error) {
	address := cfg.Proxy.Upstream
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	target, err := url.Parse(address)
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || (target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.New("proxy upstream must be an http(s) host with an optional port, without credentials or a path")
	}
	if cfg.Proxy.MaxConnections < 1 {
		return nil, errors.New("proxy max connections must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{target: target, redirect: cfg.Proxy.IPv4Redirect, logger: logger, timeout: cfg.Proxy.WriteTimeout, slots: make(chan struct{}, cfg.Proxy.MaxConnections), tunnels: make(map[net.Conn]struct{}), handoffs: &upgradeHandoffs{}}
	address = target.Host
	if target.Port() == "" {
		port := "80"
		if target.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(target.Hostname(), port)
	}
	h.client = &fasthttp.HostClient{
		Addr: address, IsTLS: target.Scheme == "https", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Hostname()},
		MaxConns: cfg.Proxy.MaxConnections, MaxIdleConnDuration: cfg.Proxy.IdleTimeout,
		ReadTimeout: cfg.Proxy.ReadTimeout, WriteTimeout: cfg.Proxy.WriteTimeout,
		MaxIdemponentCallAttempts: 1, DisablePathNormalizing: true,
		StreamResponseBody: true, NoDefaultUserAgentHeader: true, SecureErrorLogMessage: true,
	}
	if err := h.configureRoutes(cfg, logger); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

func (h *Handler) configureRoutes(cfg config.Config, logger *slog.Logger) error {
	h.routes = make(map[string]*Handler, len(cfg.Proxy.Routes))
	for host, origin := range cfg.Proxy.Routes {
		name := normalizeHost(host)
		if name == "" {
			return errors.New("upstream route hostname is empty")
		}
		if _, exists := h.routes[name]; exists {
			return errors.New("duplicate normalized upstream route hostname")
		}
		routeConfig := cfg
		routeConfig.Proxy.Upstream, routeConfig.Proxy.Routes = origin, nil
		route, err := New(routeConfig, logger)
		if err != nil {
			return fmt.Errorf("invalid upstream route for %q: %w", name, err)
		}
		h.routes[name] = route
		route.handoffs = h.handoffs
	}
	return nil
}

func normalizeHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

func (h *Handler) Handle(c fiber.Ctx) error {
	if h.closed.Load() {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	host := string(c.Request().Header.Host())
	if route := h.routes[normalizeHost(host)]; route != nil {
		return route.Handle(c)
	}
	hostname := host
	if name, _, err := net.SplitHostPort(host); err == nil {
		hostname = name
	}
	if ip := net.ParseIP(strings.Trim(hostname, "[]")); ip != nil && ip.To4() != nil && h.redirect != "" {
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(h.redirect)
	}
	select {
	case h.slots <- struct{}{}:
	default:
		return h.fail(c, fasthttp.ErrNoFreeConns)
	}
	owned := true
	release := func() { <-h.slots }
	defer func() {
		if owned {
			release()
		}
	}()
	request, upgradeProtocol := h.prepareRequest(c, host)
	defer fasthttp.ReleaseRequest(request)
	if upgradeProtocol != "" {
		owned = false
		return h.upgrade(c, request, upgradeProtocol, release)
	}
	response := fasthttp.AcquireResponse()
	if err := h.client.Do(request, response); err != nil {
		fasthttp.ReleaseResponse(response)
		return h.fail(c, err)
	}
	forwardResponse(c, response, release)
	owned = false
	if c.RequestCtx().IsTLS() {
		c.Set("Strict-Transport-Security", "max-age=0")
	}
	return nil
}

func (h *Handler) fail(c fiber.Ctx, err error) error {
	c.Response().Reset()
	status := fiber.StatusBadGateway
	var neterr net.Error
	if errors.Is(err, fasthttp.ErrTimeout) || (errors.As(err, &neterr) && neterr.Timeout()) {
		status = fiber.StatusGatewayTimeout
	}
	if errors.Is(err, fasthttp.ErrNoFreeConns) {
		status = fiber.StatusServiceUnavailable
		c.Set("Retry-After", "1")
	}
	h.logError(c, err)
	return c.SendStatus(status)
}

func (h *Handler) prepareRequest(c fiber.Ctx, host string) (*fasthttp.Request, string) {
	request := fasthttp.AcquireRequest()
	// The firewall owns the immutable body through c.Next. Copying only headers
	// avoids a second body-sized allocation outside its global memory budget.
	c.Request().Header.CopyTo(&request.Header)
	request.SetBodyRaw(c.Request().Body())
	request.SetRequestURIBytes(c.Request().Header.RequestURI())
	request.URI().DisablePathNormalizing = true
	request.URI().SetScheme(h.target.Scheme)
	request.URI().SetHost(h.target.Host)
	request.UseHostHeader = true
	upgradeProtocol := string(request.Header.Peek("Upgrade"))
	if !validUpgradeProtocol(upgradeProtocol) || !hasToken(string(request.Header.Peek("Connection")), "upgrade") {
		upgradeProtocol = ""
	}
	stripRequestHopHeaders(&request.Header)
	request.Header.SetHost(host)
	request.Header.Del("Forwarded")
	request.Header.Del("X-Real-IP")
	request.Header.Del("CF-Connecting-IP")
	request.Header.Set("X-Forwarded-For", firewall.ClientIP(c))
	request.Header.Set("X-Forwarded-Host", host)
	proto := "http"
	if c.RequestCtx().IsTLS() {
		proto = "https"
	}
	request.Header.Set("X-Forwarded-Proto", proto)
	return request, upgradeProtocol
}

func (h *Handler) logError(c fiber.Ctx, err error) {
	// One bounded message per interval keeps an upstream outage from becoming
	// a synchronous logging bottleneck. Request metrics still count every error.
	h.mu.Lock()
	emit := time.Since(h.lastError) >= time.Second
	if emit {
		h.lastError = time.Now()
	}
	h.mu.Unlock()
	if emit {
		h.logger.WarnContext(c.Context(), "upstream request failed", "client_ip", firewall.ClientIP(c), "error_type", fmt.Sprintf("%T", err))
	}
}

func (h *Handler) Close() error {
	h.closed.Store(true)
	h.mu.Lock()
	for conn := range h.tunnels {
		_ = conn.Close()
	}
	h.mu.Unlock()
	h.client.CloseIdleConnections()
	for _, route := range h.routes {
		_ = route.Close()
	}
	return nil
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripRequestHopHeaders(header *fasthttp.RequestHeader) {
	for _, token := range strings.Split(string(header.Peek("Connection")), ",") {
		if token = strings.TrimSpace(token); token != "" {
			header.Del(token)
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}

func stripResponseHopHeaders(header *fasthttp.ResponseHeader) {
	for _, token := range strings.Split(string(header.Peek("Connection")), ",") {
		if token = strings.TrimSpace(token); token != "" {
			header.Del(token)
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
	header.SetServer(config.ServerName)
}

func hasToken(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}

func validUpgradeProtocol(protocol string) bool {
	if protocol == "" {
		return false
	}
	for _, ch := range protocol {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~/", ch) {
			continue
		}
		return false
	}
	return true
}
