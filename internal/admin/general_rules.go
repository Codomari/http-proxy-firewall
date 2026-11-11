package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/ipfirewall"

	"github.com/gofiber/fiber/v3"
)

// Byte counts exposed to the browser must round-trip as exact JSON integers.
const maxAdminByteCount int64 = 1<<53 - 1

type generalRulesSource interface {
	SetGeneralRules(config.GeneralRules) error
}

type upstreamSettingsSource interface {
	SetRequestRetryTimes(int)
}

// SetUpstreamSettings connects live proxy settings before mounting routes.
func (h *Handler) SetUpstreamSettings(source upstreamSettingsSource) { h.upstream = source }

type connectionSettingsSource interface{ SetConnectionLimits(config.ConnectionLimits) }

// SetConnectionSettings connects live limits before mounting the admin routes.
func (h *Handler) SetConnectionSettings(source connectionSettingsSource) { h.connections = source }

type generalRulesSnapshot struct {
	config.GeneralRules
	IPFirewall                ipfirewall.Status `json:"ip_firewall"`
	MaxBodyBytesCeiling       int64             `json:"max_body_bytes_ceiling"`
	MaxBufferedBytesCeiling   int64             `json:"max_buffered_bytes_ceiling"`
	ActiveMaxBufferedBytes    int64             `json:"active_max_buffered_bytes"`
	Restart                   restartSnapshot   `json:"restart"`
	Available                 bool              `json:"available"`
	Overrides                 []string          `json:"overrides"`
	UpstreamAvailable         bool              `json:"upstream_available"`
	ConnectionLimitsAvailable bool              `json:"connection_limits_available"`
}

func (h *Handler) generalRulesSnapshot() (generalRulesSnapshot, error) {
	rules, err := h.generalFile.Read()
	if err != nil {
		return generalRulesSnapshot{}, err
	}
	result := generalRulesSnapshot{GeneralRules: rules, Available: h.general != nil, Overrides: h.generalFile.ProcessOverrides(), UpstreamAvailable: h.upstream != nil, ConnectionLimitsAvailable: h.connections != nil}
	result.MaxBodyBytesCeiling = h.bodyLimitCeiling
	result.MaxBufferedBytesCeiling = maxAdminByteCount
	result.ActiveMaxBufferedBytes = h.startup.Firewall.MaxBufferedBytes
	result.Restart = h.restartStatusLocked()
	if source, ok := h.general.(interface{ IPFirewallStatus() ipfirewall.Status }); ok {
		result.IPFirewall = source.IPFirewallStatus()
	} else {
		result.IPFirewall = ipfirewall.New("", nil).Status()
	}
	return result, nil
}

func (h *Handler) serveGeneralRules(c fiber.Ctx) error {
	if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead && c.Method() != fiber.MethodPost {
		c.Set("Allow", "GET, HEAD, POST")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
	if c.Method() == fiber.MethodPost {
		if c.Get("X-PF-Admin") != "1" || c.Get("Sec-Fetch-Site") == "cross-site" {
			return c.Status(403).JSON(fiber.Map{"error": "Same-origin admin request required"})
		}
		mediaType, _, err := mime.ParseMediaType(c.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return c.Status(415).JSON(fiber.Map{"error": "Send settings as application/json"})
		}
		if h.general == nil {
			return c.Status(503).JSON(fiber.Map{"error": "General rules are unavailable"})
		}
		const limit = 64 << 10
		if c.Request().Header.ContentLength() > limit {
			return c.Status(413).JSON(fiber.Map{"error": "Settings are limited to 64 KiB"})
		}
		reader := c.Request().BodyStream()
		if reader == nil {
			reader = bytes.NewReader(c.Request().Body())
		}
		data, err := io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil || len(data) > limit {
			return c.Status(413).JSON(fiber.Map{"error": "Unable to read settings within the 64 KiB limit"})
		}
		var input struct {
			MaxBodyBytes                   *int64    `json:"max_body_bytes"`
			MaxBufferedBytes               *int64    `json:"max_buffered_bytes"`
			HTTP2Enable                    *bool     `json:"http2_enable"`
			IdleRequestTimeout             *string   `json:"idle_request_timeout"`
			GCPercent                      *int      `json:"gc_percent"`
			GCMemoryLimit                  *string   `json:"gc_memory_limit"`
			WhitelistIPs                   []string  `json:"whitelist_ips"`
			WhitelistNetworks              []string  `json:"whitelist_networks"`
			IPFirewallProviders            *[]string `json:"ip_firewall_providers"`
			IPFirewallNetworks             *[]string `json:"ip_firewall_networks"`
			AllowedCountries               []string  `json:"allowed_countries"`
			IPCheckpoint                   *bool     `json:"ip_checkpoint"`
			CountryCheckpoint              *bool     `json:"country_checkpoint"`
			DDoSThreshold                  *uint64   `json:"ddos_threshold"`
			UpstreamRequestRetryTimes      *int      `json:"upstream_request_retry_times"`
			MaxConcurrentRequests          *int      `json:"max_concurrent_requests"`
			UpstreamMaxConnections         *int      `json:"upstream_max_connections"`
			UpstreamAllowOverflow          *bool     `json:"upstream_allow_overflow"`
			UpstreamMaxOverflowConnections *int      `json:"upstream_max_overflow_connections"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF || input.IPCheckpoint == nil || input.CountryCheckpoint == nil || input.DDoSThreshold == nil {
			return c.Status(400).JSON(fiber.Map{"error": "Supply whitelist lists, both checkpoint switches and a DDoS threshold as JSON"})
		}
		h.generalMu.Lock()
		defer h.generalMu.Unlock()
		// Older API clients omit newer fields; preserve their existing YAML values.
		previous, err := h.generalFile.Read()
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Unable to read general settings YAML"})
		}
		retries := previous.UpstreamRequestRetryTimes
		maxBodyBytes := previous.MaxBodyBytes
		maxBufferedBytes := previous.MaxBufferedBytes
		http2Enable, idleRequestTimeout := previous.HTTP2Enable, previous.IdleRequestTimeout
		if input.HTTP2Enable != nil {
			http2Enable = *input.HTTP2Enable
		}
		if input.IdleRequestTimeout != nil {
			idleRequestTimeout = *input.IdleRequestTimeout
			if idleRequestTimeout == "" {
				return c.Status(400).JSON(fiber.Map{"error": "Idle request timeout must be a positive duration such as 15s"})
			}
		}
		gcPercent, gcMemoryLimit := previous.GCPercent, previous.GCMemoryLimit
		providers, networks := previous.IPFirewallProviders, previous.IPFirewallNetworks
		if input.IPFirewallProviders != nil {
			providers = *input.IPFirewallProviders
		}
		if input.IPFirewallNetworks != nil {
			networks = *input.IPFirewallNetworks
		}
		if input.GCPercent != nil {
			gcPercent = *input.GCPercent
		}
		if input.GCMemoryLimit != nil {
			gcMemoryLimit = *input.GCMemoryLimit
		}
		if input.MaxBodyBytes != nil {
			maxBodyBytes = *input.MaxBodyBytes
		}
		if input.MaxBufferedBytes != nil {
			maxBufferedBytes = *input.MaxBufferedBytes
		}
		if maxBufferedBytes <= 0 || maxBufferedBytes > maxAdminByteCount {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Shared body buffer budget must be between 1 and %d bytes", maxAdminByteCount)})
		}
		if maxBodyBytes <= 0 || maxBodyBytes > h.bodyLimitCeiling {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Maximum request body size must be between 1 and %d bytes to fit the active shared inspection-buffer budget. Save a larger buffer budget and restart before increasing the body size beyond this limit", h.bodyLimitCeiling)})
		}
		limits := previous.ConnectionLimits
		if input.MaxConcurrentRequests != nil || input.UpstreamMaxConnections != nil || input.UpstreamAllowOverflow != nil || input.UpstreamMaxOverflowConnections != nil {
			if h.connections == nil {
				return c.Status(503).JSON(fiber.Map{"error": "Connection settings are unavailable"})
			}
			if input.MaxConcurrentRequests != nil {
				limits.MaxConcurrentRequests = *input.MaxConcurrentRequests
			}
			if input.UpstreamMaxConnections != nil {
				limits.UpstreamMaxConnections = *input.UpstreamMaxConnections
			}
			if input.UpstreamAllowOverflow != nil {
				limits.UpstreamAllowOverflow = *input.UpstreamAllowOverflow
			}
			if input.UpstreamMaxOverflowConnections != nil {
				limits.UpstreamMaxOverflowConnections = *input.UpstreamMaxOverflowConnections
			}
		}
		if input.UpstreamRequestRetryTimes != nil {
			if h.upstream == nil {
				return c.Status(503).JSON(fiber.Map{"error": "Upstream settings are unavailable"})
			}
			retries = *input.UpstreamRequestRetryTimes
		}
		rules, err := (config.GeneralRules{ConnectionLimits: limits, MaxBodyBytes: maxBodyBytes, MaxBufferedBytes: maxBufferedBytes, HTTP2Enable: http2Enable, IdleRequestTimeout: idleRequestTimeout, GCPercent: gcPercent, GCMemoryLimit: gcMemoryLimit, WhitelistIPs: input.WhitelistIPs, WhitelistNetworks: input.WhitelistNetworks, IPFirewallProviders: providers, IPFirewallNetworks: networks, AllowedCountries: input.AllowedCountries, IPCheckpoint: *input.IPCheckpoint, CountryCheckpoint: *input.CountryCheckpoint, DDoSThreshold: *input.DDoSThreshold, UpstreamRequestRetryTimes: retries}).Normalize()
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err := h.generalFile.Save(rules); err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Unable to save override YAML. Check file and directory permissions, YAML syntax and disk space; reload before retrying."})
		}
		if err := h.general.SetGeneralRules(rules); err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Settings saved to override YAML; restart the service to apply them"})
		}
		if h.upstream != nil {
			h.upstream.SetRequestRetryTimes(rules.UpstreamRequestRetryTimes)
		}
		if h.connections != nil {
			h.connections.SetConnectionLimits(rules.ConnectionLimits)
		}
		result, err := h.generalRulesSnapshot()
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Settings saved, but unable to reload the override YAML"})
		}
		return c.JSON(result)
	}
	h.generalMu.Lock()
	defer h.generalMu.Unlock()
	result, err := h.generalRulesSnapshot()
	if err != nil {
		return c.Status(503).JSON(fiber.Map{"error": "Unable to read general settings. Check configuration YAML permissions and syntax."})
	}
	return c.JSON(result)
}
