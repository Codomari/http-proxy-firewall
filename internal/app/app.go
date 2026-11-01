// Package app is the composition root. Business components do not depend on Fx.
package app

import (
	"context"
	"log/slog"
	"os"
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"http-proxy-firewall/internal/admin"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/firewall"
	"http-proxy-firewall/internal/intelligence"
	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/proxy"
	"http-proxy-firewall/internal/server"
	"http-proxy-firewall/internal/session"
	"http-proxy-firewall/internal/storage"
)

func New(cfg config.Config, options ...fx.Option) *fx.App {
	base := []fx.Option{
		fx.Supply(cfg),
		fx.Provide(
			newLogger,
			storage.New,
			intelligence.New,
			session.New,
			newFirewall,
			monitoring.New,
			newAdmin,
			proxy.New,
			server.New),
		fx.Invoke(registerLifecycle),
		fx.WithLogger(func(logger *slog.Logger) fxevent.Logger {
			return &fxevent.SlogLogger{Logger: logger}
		}),
		fx.StartTimeout(30 * time.Second),
		fx.StopTimeout(30 * time.Second),
	}
	return fx.New(append(base, options...)...)
}

func newLogger(cfg config.Config) *slog.Logger {
	level := slog.LevelInfo
	if cfg.Observability.Silent {
		level = slog.LevelWarn
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func newFirewall(cfg config.Config, sources *intelligence.Service, sessions *session.Service, logger *slog.Logger) (*firewall.Engine, error) {
	return firewall.New(cfg, sources, sessions, logger)
}

func newAdmin(cfg config.Config, stats *monitoring.Registry, rules *firewall.Engine, logger *slog.Logger, remote *storage.Remote, sources *intelligence.Service) (*admin.Handler, error) {
	return admin.New(cfg, stats, rules, logger, admin.ServiceSources{Redis: remote, MaxMind: sources})
}

func registerLifecycle(lifecycle fx.Lifecycle, remote *storage.Remote, sources *intelligence.Service, upstream *proxy.Handler, listener *server.Server, shutdown fx.Shutdowner, logger *slog.Logger) {
	lifecycle.Append(fx.Hook{OnStart: remote.Start, OnStop: remote.Stop})
	lifecycle.Append(fx.Hook{OnStart: sources.Start, OnStop: sources.Stop})
	lifecycle.Append(fx.Hook{OnStop: func(context.Context) error { return upstream.Close() }})
	var stopWatching context.CancelFunc
	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := listener.Start(ctx); err != nil {
				return err
			}
			var watch context.Context
			watch, stopWatching = context.WithCancel(context.Background())
			go watchListener(watch, listener.Errors(), shutdown, logger)
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if stopWatching != nil {
				stopWatching()
			}
			return listener.Stop(ctx)
		},
	})
}

func watchListener(ctx context.Context, failures <-chan error, shutdown fx.Shutdowner, logger *slog.Logger) {
	select {
	case <-ctx.Done():
	case err, ok := <-failures:
		if ok && err != nil {
			logger.Error("listener stopped unexpectedly", "error", err)
			if err := shutdown.Shutdown(fx.ExitCode(1)); err != nil {
				logger.Error("request shutdown", "error", err)
			}
		}
	}
}
