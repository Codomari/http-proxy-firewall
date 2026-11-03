// Package firewall inspects every body before forwarding or allowing bypasses.
// CVE checks add defense in depth; they do not replace upstream PHP patches.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/netip"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"

	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/config"
	cve2026109618 "http-proxy-firewall/internal/firewall/cves/2026-109618"
	"http-proxy-firewall/internal/session"
)

type Intelligence interface {
	Country(context.Context, netip.Addr) string
	IsGoogleBot(netip.Addr) bool
}

type Engine struct {
	limits          cve2026109618.Limits
	uploadNames     []string
	trustedProxies  []netip.Prefix
	general         atomic.Pointer[generalRules]
	trustCloudflare bool
	cloudflare      cloudflareSettings
	intelligence    Intelligence
	sessions        *session.Service
	logger          *slog.Logger
	rejectionLogs   rejectionSampler
	budget          byteBudget
	detector        detector
	now             func() time.Time
	trackInput      bool
}

func New(cfg config.Config, intelligence Intelligence, sessions *session.Service, logger *slog.Logger) (*Engine, error) {
	f := cfg.Firewall
	if f.MaxBodyBytes <= 0 {
		f.MaxBodyBytes = cve2026109618.DefaultMaxBodyBytes
	}
	if f.MaxBodyBytes >= int64(math.MaxInt) {
		return nil, errors.New("request body limit must fit int with an overflow probe")
	}
	if f.MaxBufferedBytes <= 0 {
		f.MaxBufferedBytes = 256 << 20
	}
	if f.MaxBufferedBytes < f.MaxBodyBytes+1 {
		return nil, errors.New("buffer budget must allow one complete request body plus overflow probe")
	}
	if f.RequestThreshold == 0 {
		f.RequestThreshold = 200
	}
	if f.SamplingWindow <= 0 {
		f.SamplingWindow = 10 * time.Second
	}
	if f.SamplingWindow < time.Second || f.SamplingWindow%time.Second != 0 {
		return nil, errors.New("sampling window must be a whole number of seconds")
	}
	if f.PenaltyLifetime <= 0 {
		f.PenaltyLifetime = 10 * time.Minute
	}
	if f.CacheCapacity <= 0 {
		f.CacheCapacity = 100000
	}
	if f.RejectionLogInterval < 0 {
		return nil, errors.New("rejection log interval cannot be negative")
	}
	general, err := compileGeneralRules(config.GeneralRulesFromFirewall(f))
	if err != nil {
		return nil, err
	}
	trusted, err := parseNetworks(f.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if sessions == nil {
		sessions = session.New(cfg, nil)
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	e := &Engine{
		limits:          cve2026109618.Limits{MaxBodyBytes: f.MaxBodyBytes},
		uploadNames:     append([]string(nil), f.UploadProgressNames...),
		trustedProxies:  trusted,
		trustCloudflare: f.TrustCloudflareHeader,
		intelligence:    intelligence, sessions: sessions, logger: logger,
		rejectionLogs: rejectionSampler{interval: f.RejectionLogInterval},
		budget:        byteBudget{limit: f.MaxBufferedBytes},
		detector:      detector{hosts: cache.New[string, hostWindow](f.CacheCapacity), window: f.SamplingWindow, penalty: f.PenaltyLifetime, threshold: f.RequestThreshold},
		now:           time.Now,
		trackInput:    cfg.Admin.Enabled,
	}
	e.general.Store(general)
	if err := e.cloudflare.load(f.CloudflareHostsFile); err != nil {
		return nil, fmt.Errorf("load Cloudflare hostname settings: %w", err)
	}
	return e, nil
}

func (e *Engine) Handler(c fiber.Ctx) error {
	address := e.clientAddress(c)
	// Always keep body validation first, including static files, whitelisted
	// clients, accepted cookies, and search engine ranges.
	release, err := e.inspect(c)
	if release != nil {
		defer release()
	}
	if err != nil {
		return err
	}
	if c.Response().StatusCode() >= 400 {
		return nil
	}
	if hasSensitiveQuery(c) && isBot(string(c.Request().Header.UserAgent())) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	host, err := normalizeHostname(string(c.Request().Header.Host()))
	if err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}
	if isStatic(string(c.Request().URI().Path())) || e.bypass(c.Context(), address) {
		return c.Next()
	}
	if !e.detector.penalized(host, e.now()) {
		return c.Next()
	}
	if e.sessions.Validate(c.Context(), c.Cookies(session.CookieName), host, string(c.Request().Header.UserAgent())) {
		return c.Next()
	}
	return e.challenge(c, host)
}

func (e *Engine) bypass(ctx context.Context, address netip.Addr) bool {
	if matched, bypass := e.whitelistBypass(ctx, address); matched {
		return bypass
	}
	if e.intelligence == nil {
		return false
	}
	if e.intelligence.IsGoogleBot(address) {
		return true
	}
	return false
}

func (e *Engine) challenge(c fiber.Ctx, host string) error {
	record, err := e.sessions.Issue(c.Context(), host, string(c.Request().Header.UserAgent()))
	if err != nil {
		e.logger.Error("session challenge failed", "client_ip", ClientIP(c), "error", err)
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	domain := host
	if _, err := netip.ParseAddr(host); err == nil {
		domain = ""
	}
	c.Cookie(&fiber.Cookie{
		Name: session.CookieName, Value: record.SID, Path: "/", Domain: domain,
		MaxAge: int(e.sessions.Lifetime() / time.Second), Expires: record.Expires,
		Secure: c.Secure(), HTTPOnly: true, SameSite: "Lax",
	})
	c.Set("Content-Type", "text/html; charset=utf-8")
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusOK).SendString(`<meta http-equiv="refresh" content="0">`)
}

func isStatic(requestPath string) bool {
	extension := strings.ToLower(path.Ext(requestPath))
	switch extension {
	case ".css", ".js", ".htm", ".html", ".txt":
		return true
	}
	return strings.HasPrefix(mime.TypeByExtension(extension), "image/")
}

func hasSensitiveQuery(c fiber.Ctx) bool {
	if len(c.Request().URI().QueryString()) == 0 {
		return false
	}
	query := c.Request().URI().QueryArgs()
	for _, key := range sensitiveQueryKeys {
		if query.Has(key) {
			return true
		}
	}
	return false
}

var sensitiveQueryKeys = [...]string{"ps", "pw", "pwd", "pass", "password", "secret", "api_key", "tkn", "token", "access_token"}

var botAgents = [...]string{
	"googlebot", "googlebot-image", "googlebot-news", "googlebot-video", "adsbot-google", "mediapartners-google", "apis-google",
	"feedfetcher-google", "appengine-google", "google-read-aloud", "google-searchbyimage", "google-searchbyvoice", "google-favicon",
	"google-searchconsole", "google-structureddatatestingtool", "google-adwords", "ahrefsbot", "bingbot", "yandexbot", "yandeximages",
	"yandexvideo", "yandexblogs", "yandexfavicons", "yandexwebmaster", "yandexpagechecker", "yandeximageresizer", "yandexdirect",
	"yandexmetrika", "yandexcatalog", "yandexmarket", "yandexmediana", "yandexmedia", "yandexnews", "yandexcalendar",
	"yandexsitelinks", "yandexantivirus", "yandexvertis", "yandexflights", "yandexadnet", "amazonbot", "slurp", "msnbot", "bingpreview", "adidxbot",
}

func isBot(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)
	for _, bot := range botAgents {
		if strings.Contains(userAgent, bot) {
			return true
		}
	}
	return false
}
