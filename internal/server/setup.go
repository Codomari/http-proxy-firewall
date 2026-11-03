package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/observability"
	"http-proxy-firewall/internal/proxy"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"golang.org/x/crypto/acme/autocert"
)

type originalMethodKey struct{}

const extensionMethod = "OTHER"

func newFiberApp(cfg config.Config) *fiber.App {
	methods := append(append([]string(nil), fiber.DefaultMethods...), extensionMethod)
	return fiber.New(fiber.Config{
		ServerHeader:  config.ServerName,
		CaseSensitive: true, StrictRouting: true, DisableFlashMessages: true,
		RequestMethods: methods, StreamRequestBody: true, DisablePreParseMultipartForm: true,
		BodyLimit: int(cfg.Firewall.MaxBodyBytes), Concurrency: cfg.HTTP.MaxConnections,
		ReadTimeout: cfg.HTTP.ReadTimeout, WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout,
		ErrorHandler: func(c fiber.Ctx, err error) error {
			status := fiber.StatusInternalServerError
			var ferr *fiber.Error
			if errors.As(err, &ferr) {
				status = ferr.Code
			}
			return c.Status(status).SendString(http.StatusText(status))
		},
	})
}

func (s *Server) configureRoutes(engine *firewall.Engine, upstream *proxy.Handler) {
	s.app.Use(func(c fiber.Ctx) error {
		if method, ok := c.RequestCtx().UserValue(originalMethodKey{}).(string); ok {
			c.Request().Header.SetMethod(method)
		}
		return c.Next()
	})
	if s.cfg.TLS.Enabled && s.cfg.TLS.CertificateFile == "" {
		s.configureACME()
	}
	s.adminUI.Mount(s.app)
	s.app.Use(s.adminUI.DebugMiddleware(engine.ResolveClientIP))
	if s.cfg.Observability.Metrics {
		monitor := observability.New()
		monitor.Mount(s.app)
		s.app.Use(monitor.Handler)
	}
	s.app.Use(s.stats.Middleware(firewall.CanonicalHostname))
	s.app.Use(s.admissionHandler())
	s.app.Use(engine.Handler)
	s.app.Use(upstream.Handle)
}

func (s *Server) configureACME() {
	s.manager = &autocert.Manager{Prompt: autocert.AcceptTOS, Email: s.cfg.TLS.Email, Cache: autocert.DirCache(s.cfg.TLS.CacheDir), HostPolicy: hostPolicy(s.cfg.TLS.Hosts)}
	challenge := fasthttpadaptor.NewFastHTTPHandler(s.manager.HTTPHandler(http.NotFoundHandler()))
	s.app.Use(func(c fiber.Ctx) error {
		if strings.HasPrefix(string(c.Request().Header.RequestURI()), "/.well-known/acme-challenge/") {
			challenge(c.RequestCtx())
			return nil
		}
		return c.Next()
	})
}

func (s *Server) admissionHandler() fiber.Handler {
	requests := make(chan struct{}, s.cfg.HTTP.MaxConcurrentRequests)
	return func(c fiber.Ctx) (err error) {
		select {
		case requests <- struct{}{}:
		default:
			c.Set("Retry-After", "1")
			return c.SendStatus(fiber.StatusServiceUnavailable)
		}
		defer func() {
			<-requests
			if value := recover(); value != nil {
				s.logger.Error("request handler panic", "panic_type", fmt.Sprintf("%T", value))
				err = fiber.ErrInternalServerError
			}
		}()
		return c.Next()
	}
}

func (s *Server) configureHTTPServer(upstream *proxy.Handler) {
	// Prepare routing synchronously, before either listener accepts traffic.
	handler := s.app.Handler()
	fast := s.app.Server()
	fast.ConnState = func(conn net.Conn, state fasthttp.ConnState) {
		if state == fasthttp.StateClosed {
			upstream.AbortPendingUpgrade(conn)
		}
	}
	fast.Handler = func(ctx *fasthttp.RequestCtx) {
		method := string(ctx.Request.Header.Method())
		known := method == extensionMethod
		for _, candidate := range fiber.DefaultMethods {
			if method == candidate {
				known = true
				break
			}
		}
		if !known {
			// Keep a fixed routing table while allowing all extension methods to
			// reach body inspection. Restore the real method before middleware.
			ctx.SetUserValue(originalMethodKey{}, method)
			ctx.Request.Header.SetMethod(extensionMethod)
		}
		handler(ctx)
		ctx.Response.Header.SetServer(config.ServerName)
	}
	// HeaderReceived runs after complete headers and extends only the body
	// deadline. Slow headers retain the original ten-second deadline.
	fast.ReadTimeout = 10 * time.Second
	fast.HeaderReceived = func(*fasthttp.RequestHeader) fasthttp.RequestConfig {
		return fasthttp.RequestConfig{ReadTimeout: s.cfg.HTTP.ReadTimeout, WriteTimeout: s.cfg.HTTP.WriteTimeout}
	}
	fast.Logger = &safeLogger{logger: s.logger}
	fast.SecureErrorLogMessage = true
}

func newAdminServer(address string) (*http.Server, error) {
	if address == "" {
		return nil, nil
	}
	if err := validateAdminAddress(address); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute}, nil
}
