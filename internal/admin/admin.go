// Package admin serves the embedded, authenticated operational dashboard.
package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	buildinfo "http-proxy-firewall"

	"github.com/gofiber/fiber/v3"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/intelligence"
	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/storage"
)

const BasePath = "/" + config.DefaultAdminURI

//go:embed assets/*
var embedded embed.FS

type PenaltySource interface {
	DDoSState(host string) (bool, time.Time)
}

type ServiceSources struct {
	Redis   interface{ Snapshot() storage.Snapshot }
	MaxMind interface {
		DatabaseStatus() intelligence.DatabaseSnapshot
	}
}

type serviceSnapshot struct {
	Redis   storage.Snapshot              `json:"redis"`
	MaxMind intelligence.DatabaseSnapshot `json:"maxmind"`
}

type credentialHashes struct {
	user, password [sha256.Size]byte
}

type Handler struct {
	basePath         string
	enabled          bool
	accounts         []credentialHashes
	registry         *monitoring.Registry
	penalties        PenaltySource
	services         ServiceSources
	assets           map[string][]byte
	logs             logTail
	debug            debugLog
	cloudflare       cloudflareSource
	general          generalRulesSource
	bodyLimitCeiling int64
	startup          config.Config
	restart          func() error
	restartPending   bool
	upstream         upstreamSettingsSource
	connections      connectionSettingsSource
	generalFile      config.GeneralRulesFile
	generalMu        sync.Mutex
	certBlacklist    CertificateBlacklist
	certificates     CertificateService
	testPages        []TestPage
}

func New(cfg config.Config, registry *monitoring.Registry, penalties PenaltySource, logger *slog.Logger, services ...ServiceSources) (*Handler, error) {
	basePath, err := config.AdminPath(cfg.Admin.URI)
	if err != nil {
		return nil, err
	}
	if cfg.Admin.Enabled && len(cfg.Admin.Accounts) == 0 {
		return nil, errors.New("enabled admin requires at least one account")
	}
	if cfg.Admin.Enabled && registry == nil {
		return nil, errors.New("enabled admin requires a monitoring registry")
	}
	h := &Handler{basePath: basePath, enabled: cfg.Admin.Enabled, registry: registry, penalties: penalties, assets: make(map[string][]byte, 4)}
	h.logs.path = "log/proxy-firewall.log"
	h.debug.dir = "log"
	h.cloudflare, _ = penalties.(cloudflareSource)
	h.general, _ = penalties.(generalRulesSource)
	h.startup = cfg
	h.bodyLimitCeiling = min(cfg.Firewall.MaxBufferedBytes-1, maxAdminByteCount)
	h.generalFile.Path = config.OverrideYAML
	h.generalFile.Store = cfg.Source
	if cfg.Source != nil {
		if err := h.debug.loadConfig(cfg.Source); err != nil {
			return nil, err
		}
	}
	for _, account := range cfg.Admin.Accounts {
		if account.User == "" || account.Password == "" {
			return nil, errors.New("admin accounts require both user and password")
		}
		h.accounts = append(h.accounts, credentialHashes{user: sha256.Sum256([]byte(account.User)), password: sha256.Sum256([]byte(account.Password))})
	}
	if len(services) > 0 {
		h.services = services[0]
	}
	for _, name := range []string{"admin.html", "admin.css", "admin.js", "favicon.svg"} {
		data, err := embedded.ReadFile("assets/" + name)
		if err != nil {
			return nil, errors.New("embedded admin asset is unavailable")
		}
		data = bytes.ReplaceAll(data, []byte("__PF_VERSION__"), []byte(buildinfo.Version))
		h.assets[name] = bytes.ReplaceAll(data, []byte(BasePath), []byte(basePath))
	}
	return h, nil
}

// Mount must run before request monitoring, admission, and firewall middleware.
// The reserved subtree is always handled, including when admin is disabled.
func (h *Handler) Mount(app *fiber.App) {
	app.Use(func(c fiber.Ctx) error {
		resolved, owned := ownedPath(c.Path(), h.basePath)
		if !owned {
			h.stripAdminCredentials(c)
			return c.Next()
		}
		return h.serve(c, resolved)
	})
}

// A browser can reuse cached Basic credentials on neighboring paths. Remove
// our configured pairs before forwarding, including after disabling the
// dashboard, while preserving every unrelated backend Authorization value.
func (h *Handler) stripAdminCredentials(c fiber.Ctx) {
	if len(h.accounts) == 0 {
		return
	}
	header := &c.Request().Header
	values := header.PeekAll("Authorization")
	matched := false
	for _, value := range values {
		if h.authorized(string(value)) {
			matched = true
			break
		}
	}
	if !matched {
		return
	}
	retained := make([][]byte, 0, len(values))
	for _, value := range values {
		if !h.authorized(string(value)) {
			retained = append(retained, bytes.Clone(value))
		}
	}
	header.Del("Authorization")
	for _, value := range retained {
		header.AddBytesV("Authorization", value)
	}
}

func pathHasBase(value, basePath string) bool {
	return len(value) >= len(basePath) && strings.EqualFold(value[:len(basePath)], basePath) && (len(value) == len(basePath) || value[len(basePath)] == '/')
}

func ownedPath(raw, basePath string) (string, bool) {
	direct := pathHasBase(raw, basePath)
	if !direct && !strings.ContainsAny(raw, "%\\") && !strings.Contains(raw, "//") {
		return "", false
	}
	decoded := raw
	// Bound decoding work while owning common multiply-encoded reserved paths.
	for i := 0; i < 3 && strings.ContainsRune(decoded, '%'); i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", direct
		}
		decoded = next
	}
	resolved := path.Clean(strings.ReplaceAll(decoded, "\\", "/"))
	if pathHasBase(resolved, basePath) {
		return strings.ToLower(resolved), true
	}
	return "", direct
}

func (h *Handler) serve(c fiber.Ctx, requestPath string) error {
	// Only the authenticated general settings endpoint consumes a bounded JSON
	// body. Close other uploads without an unread-body drain.
	if c.Request().Header.ContentLength() != 0 {
		c.Response().Header.SetConnectionClose()
	}
	c.Set("Cache-Control", "no-store")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("X-Frame-Options", "DENY")
	c.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if !h.enabled {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if !h.authorized(c.Get("Authorization")) {
		c.Set("WWW-Authenticate", `Basic realm="Proxy firewall admin", charset="UTF-8"`)
		return c.Status(fiber.StatusUnauthorized).SendString("Authentication required")
	}
	if requestPath == h.basePath+"/api/test-pages" || requestPath == h.basePath+"/test/pages" || strings.HasPrefix(requestPath, h.basePath+"/test/pages/") {
		return h.serveTestPage(c, requestPath)
	}
	if requestPath == h.basePath+"/api/debug" {
		return h.serveDebug(c)
	}
	if requestPath == h.basePath+"/api/cloudflare-hosts" {
		return h.serveCloudflare(c)
	}
	if requestPath == h.basePath+"/api/general-rules" {
		return h.serveGeneralRules(c)
	}
	if requestPath == h.basePath+"/api/restart" {
		return h.serveRestart(c)
	}
	if requestPath == h.basePath+"/api/certbot-blacklist" {
		return h.serveCertificateBlacklist(c)
	}
	if requestPath == h.basePath+"/api/certificates" {
		return h.serveCertificates(c)
	}
	if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead {
		c.Set("Allow", "GET, HEAD")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
	switch requestPath {
	case h.basePath:
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Send(h.assets["admin.html"])
	case h.basePath + "/assets/admin.css":
		c.Set("Content-Type", "text/css; charset=utf-8")
		return c.Send(h.assets["admin.css"])
	case h.basePath + "/assets/admin.js":
		c.Set("Content-Type", "text/javascript; charset=utf-8")
		return c.Send(h.assets["admin.js"])
	case h.basePath + "/assets/favicon.svg":
		c.Set("Content-Type", "image/svg+xml")
		return c.Send(h.assets["favicon.svg"])
	case h.basePath + "/api/overview":
		list, err := h.hosts(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid host search"})
		}
		return c.JSON(fiber.Map{"timestamp": time.Now().UTC(), "totals": h.registry.Totals(), "runtime": h.registry.Runtime(), "hosts": list.Hosts, "host_count": list.Total, "services": h.serviceStatus(), "disks": h.registry.Disks(), "restart": h.restartStatus()})
	case h.basePath + "/api/logs":
		result, err := h.logs.read(c.Query("cursor"))
		if err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Log file is unavailable. Expected log/proxy-firewall.log in the service working directory."})
		}
		return c.JSON(result)
	case h.basePath + "/api/debug/logs":
		return h.serveDebugLogs(c)
	case h.basePath + "/api/hosts":
		list, err := h.hosts(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid host search"})
		}
		return c.JSON(list)
	case h.basePath + "/api/runtime":
		return c.JSON(fiber.Map{"timestamp": time.Now().UTC(), "runtime": h.registry.Runtime()})
	default:
		return c.SendStatus(fiber.StatusNotFound)
	}
}

func (h *Handler) authorized(header string) bool {
	if len(header) > 4096 {
		return false
	}
	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	user, password, ok := bytes.Cut(decoded, []byte(":"))
	if !ok {
		return false
	}
	userHash, passwordHash := sha256.Sum256(user), sha256.Sum256(password)
	matched := 0
	for _, account := range h.accounts {
		matched |= subtle.ConstantTimeCompare(userHash[:], account.user[:]) & subtle.ConstantTimeCompare(passwordHash[:], account.password[:])
	}
	return matched == 1
}

type hostRow struct {
	monitoring.HostSnapshot
	DDoS      bool       `json:"ddos"`
	DDoSUntil *time.Time `json:"ddos_until,omitempty"`
}

type hostsList struct {
	Timestamp time.Time `json:"timestamp"`
	Hosts     []hostRow `json:"hosts"`
	Total     int       `json:"total"`
}

func (h *Handler) hosts(c fiber.Ctx) (hostsList, error) {
	search := c.Query("search")
	if len(search) > 256 {
		return hostsList{}, errors.New("search too long")
	}
	search = strings.ToLower(search)
	hosts := h.registry.Hosts()
	filtered := hosts[:0]
	for _, host := range hosts {
		if search == "" || strings.Contains(strings.ToLower(host.Hostname), search) {
			filtered = append(filtered, host)
		}
	}
	rows := make([]hostRow, 0, len(filtered))
	for _, host := range filtered {
		row := hostRow{HostSnapshot: host}
		if h.penalties != nil {
			active, until := h.penalties.DDoSState(host.Hostname)
			row.DDoS = active
			if active && !until.IsZero() {
				until = until.UTC()
				row.DDoSUntil = &until
			}
		}
		rows = append(rows, row)
	}
	return hostsList{Timestamp: time.Now().UTC(), Hosts: rows, Total: len(rows)}, nil
}

func (h *Handler) serviceStatus() serviceSnapshot {
	result := serviceSnapshot{Redis: storage.Snapshot{Status: "disabled"}}
	if h.services.Redis != nil {
		result.Redis = h.services.Redis.Snapshot()
	}
	if h.services.MaxMind != nil {
		result.MaxMind = h.services.MaxMind.DatabaseStatus()
	}
	return result
}
