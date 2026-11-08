// Package server owns listener binding, TLS, administration, and graceful drain.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"http-proxy-firewall/internal/admin"
	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/proxy"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	cfg           config.Config
	app           *fiber.App
	logger        *slog.Logger
	manager       *autocert.Manager
	certGuard     *certificateGuard
	certMu        sync.Mutex
	certRequests  map[string]admin.CertificateRequest
	certIssue     func(string) error
	usableCerts   *cache.Cache[string, bool]
	h2Base        *http.Server
	h2Conns       map[net.Conn]struct{}
	h2Stopping    bool
	admin         *http.Server
	adminUI       *admin.Handler
	stats         *monitoring.Registry
	statusCountry func(fiber.Ctx) string
	bodyLimit     func() int64
	admission     requestAdmission
	upstream      *proxy.Handler
	mu            sync.Mutex
	listeners     []net.Listener
	httpAddress   net.Addr
	tlsAddress    net.Addr
	started       bool
	stopping      bool
	restarting    atomic.Bool
	hostnames     sync.Map
	errors        chan error
	wg            sync.WaitGroup
}

func New(cfg config.Config, engine *firewall.Engine, upstream *proxy.Handler, logger *slog.Logger, stats *monitoring.Registry, adminHandler *admin.Handler) (*Server, error) {
	if engine == nil || upstream == nil {
		return nil, errors.New("server requires firewall and proxy handlers")
	}
	if cfg.Firewall.MaxBodyBytes < 1 || uint64(cfg.Firewall.MaxBodyBytes) > uint64(^uint(0)>>1) {
		return nil, errors.New("request body limit does not fit a positive int")
	}
	if cfg.HTTP.MaxConnections < 1 || cfg.HTTP.MaxConcurrentRequests < 1 {
		return nil, errors.New("server connection and request limits must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if stats == nil {
		stats = monitoring.New(cfg)
	}
	if adminHandler == nil {
		disabled := cfg
		disabled.Admin.Enabled = false
		var err error
		adminHandler, err = admin.New(disabled, stats, engine, logger)
		if err != nil {
			return nil, err
		}
	}
	s := &Server{cfg: cfg, logger: logger, errors: make(chan error, 3), stats: stats, adminUI: adminHandler, statusCountry: engine.ClientCountry}
	s.upstream = upstream
	s.bodyLimit = engine.MaxBodyBytes
	engine.SetBodyLimitPage(s.serveRequestTooLarge)
	s.admission.limit = cfg.HTTP.MaxConcurrentRequests
	basePath, err := config.AdminPath(cfg.Admin.URI)
	if err != nil {
		return nil, err
	}
	s.certGuard, err = newCertificateGuard(basePath+"/dns/test", certificateBlacklistFile, logger)
	if err != nil {
		return nil, err
	}
	s.adminUI.SetCertificateBlacklist(s.certGuard)
	s.adminUI.SetUpstreamSettings(upstream)
	s.adminUI.SetConnectionSettings(s)
	s.adminUI.SetTestPages(s.statusTestPages())
	s.certGuard.behindCloudflare = engine.BehindCloudflare
	s.certGuard.country = engine.ClientCountry
	s.certRequests = make(map[string]admin.CertificateRequest)
	s.usableCerts = cache.New[string, bool](certificateHostLimit)
	s.adminUI.SetCertificateService(s)
	s.app = newFiberApp(cfg)
	s.configureRoutes(engine, upstream)
	s.configureHTTPServer(upstream)
	s.admin, err = newAdminServer(cfg.Observability.PprofAddress)
	if err != nil {
		return nil, err
	}
	return s, nil
}

type safeLogger struct {
	logger   *slog.Logger
	hostname func(net.Addr, net.Addr) string
	mu       sync.Mutex
	next     time.Time
}

func (l *safeLogger) Printf(format string, args ...any) {
	now := time.Now()
	l.mu.Lock()
	emit := !now.Before(l.next)
	if emit {
		l.next = now.Add(time.Second)
	}
	l.mu.Unlock()
	if emit {
		attributes := []any{"client_ip", connectionClientIP(format, args), "error", connectionError(format, args)}
		if l.hostname != nil && format == "error when serving connection %q<->%q: %v" && len(args) >= 2 {
			local, localOK := args[0].(net.Addr)
			remote, remoteOK := args[1].(net.Addr)
			if localOK && remoteOK {
				if name := l.hostname(local, remote); name != "" {
					attributes = append(attributes, "hostname", name)
				}
			}
		}
		l.logger.Warn("HTTP connection failed", attributes...)
	}
}

func connectionKey(local, remote net.Addr) string {
	if local == nil || remote == nil {
		return ""
	}
	return local.String() + "\n" + remote.String()
}

func (s *Server) rememberHostname(local, remote net.Addr, raw string) {
	if name, err := firewall.CanonicalHostname(raw); err == nil {
		if key := connectionKey(local, remote); key != "" {
			s.hostnames.Store(key, strings.Clone(name))
		}
	}
}

func (s *Server) connectionHostname(local, remote net.Addr) string {
	if name, exists := s.hostnames.Load(connectionKey(local, remote)); exists {
		return name.(string)
	}
	return ""
}

func connectionError(format string, args []any) string {
	if format == "error when serving connection %q<->%q: %v" && len(args) >= 3 {
		return fmt.Sprint(args[2])
	}
	// Preserve listener errors and connection-limit diagnostics as well.
	return fmt.Sprintf(format, args...)
}

func connectionClientIP(format string, args []any) string {
	// fasthttp passes typed local/remote addresses for connection failures.
	// Headers may not exist yet; only the socket peer can be identified here.
	if format == "error when serving connection %q<->%q: %v" && len(args) >= 2 {
		if remote, ok := args[1].(net.Addr); ok && remote != nil {
			if address, err := netip.ParseAddrPort(remote.String()); err == nil {
				return address.Addr().Unmap().String()
			}
		}
	}
	if format == "The number of connections from %s exceeds MaxConnsPerIP=%d" && len(args) > 0 {
		if address, ok := args[0].(net.IP); ok && address != nil {
			return address.String()
		}
	}
	// Listener-wide failures have no associated remote address.
	return "unknown"
}

// fasthttp reports listener Close errors from Shutdown. Explicit early Close
// is needed for the startup/shutdown race, so make repeated closes harmless.
type idempotentListener struct {
	net.Listener
	once sync.Once
}

func (l *idempotentListener) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close() })
	return err
}

func hostPolicy(hosts []string) autocert.HostPolicy {
	allowed := autocert.HostWhitelist(hosts...)
	return func(ctx context.Context, host string) error {
		name := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			name = h
		}
		name = strings.TrimSuffix(strings.Trim(name, "[]"), ".")
		if net.ParseIP(name) != nil {
			return errors.New("autocert: IP addresses are not allowed")
		}
		if len(hosts) != 0 {
			return allowed(ctx, name)
		}
		return nil
	}
}

func validateAdminAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("pprof address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("pprof address must use a loopback IP")
	}
	return nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopping {
		return errors.New("server cannot be started twice")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tlsConfig, err := s.tlsConfiguration()
	if err != nil {
		return err
	}
	var listeners []net.Listener
	cleanup := func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}
	httpListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("bind HTTP: %w", err)
	}
	httpListener = &idempotentListener{Listener: httpListener}
	listeners = append(listeners, httpListener)
	var tlsListener, adminListener net.Listener
	if s.cfg.TLS.Enabled {
		raw, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.HTTP.TLSListen)
		if err != nil {
			cleanup()
			return fmt.Errorf("bind HTTPS: %w", err)
		}
		tlsListener = &idempotentListener{Listener: tls.NewListener(raw, tlsConfig)}
		listeners = append(listeners, tlsListener)
	}
	if s.admin != nil {
		adminListener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", s.admin.Addr)
		if err != nil {
			cleanup()
			return fmt.Errorf("bind pprof: %w", err)
		}
		adminListener = &idempotentListener{Listener: adminListener}
		listeners = append(listeners, adminListener)
	}
	s.listeners, s.httpAddress, s.started = listeners, httpListener.Addr(), true
	if tlsListener != nil {
		s.tlsAddress = tlsListener.Addr()
	}
	s.serve("HTTP", func() error { return s.app.Server().Serve(httpListener) })
	if tlsListener != nil {
		s.serve("HTTPS", func() error { return s.app.Server().Serve(tlsListener) })
	}
	if adminListener != nil {
		s.serve("pprof", func() error { return s.admin.Serve(adminListener) })
	}
	return nil
}

func (s *Server) tlsConfiguration() (*tls.Config, error) {
	if !s.cfg.TLS.Enabled {
		return nil, nil
	}
	minimum := uint16(tls.VersionTLS12)
	if s.cfg.TLS.AllowLegacyClients {
		minimum = tls.VersionTLS10
	}
	result := &tls.Config{MinVersion: minimum, NextProtos: []string{"h2", "http/1.1"}}
	result.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.rememberHostname(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr(), hello.ServerName)
		return nil, nil
	}
	if s.cfg.TLS.CertificateFile != "" || s.cfg.TLS.PrivateKeyFile != "" {
		pair, err := tls.LoadX509KeyPair(s.cfg.TLS.CertificateFile, s.cfg.TLS.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		result.Certificates = []tls.Certificate{pair}
	} else {
		fallback := new(hostnameRequiredCertificate)
		result.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				return fallback.get()
			}
			return s.manager.GetCertificate(hello)
		}
		result.NextProtos = append(result.NextProtos, acme.ALPNProto)
	}
	return result, nil
}

func (s *Server) serve(name string, run func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := run()
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if !stopping {
			if err == nil {
				err = errors.New("listener stopped unexpectedly")
			}
			select {
			case s.errors <- fmt.Errorf("%s listener: %w", name, err):
			default:
			}
		}
	}()
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	listeners, started := append([]net.Listener(nil), s.listeners...), s.started
	s.mu.Unlock()
	if !started {
		return nil
	}
	s.restarting.Store(true)
	waitForRestartNotice(ctx)
	s.mu.Lock()
	s.h2Stopping = true
	s.mu.Unlock()
	// Closing bound listeners also handles Stop racing before a Serve goroutine
	// has registered its listener with the underlying HTTP server.
	for _, listener := range listeners {
		_ = listener.Close()
	}
	var drainErr, adminErr error
	var drain sync.WaitGroup
	drain.Add(1)
	go func() { defer drain.Done(); drainErr = s.app.ShutdownWithContext(ctx) }()
	if s.h2Base != nil {
		drain.Add(1)
		go func() { defer drain.Done(); _ = s.h2Base.Shutdown(ctx) }()
	}
	if s.admin != nil {
		drain.Add(1)
		go func() { defer drain.Done(); adminErr = s.admin.Shutdown(ctx) }()
	}
	drain.Wait()
	if ctx.Err() != nil {
		s.mu.Lock()
		for conn := range s.h2Conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.Join(drainErr, adminErr)
}

func (s *Server) Errors() <-chan error  { return s.errors }
func (s *Server) HTTPAddress() net.Addr { s.mu.Lock(); defer s.mu.Unlock(); return s.httpAddress }
func (s *Server) TLSAddress() net.Addr  { s.mu.Lock(); defer s.mu.Unlock(); return s.tlsAddress }
