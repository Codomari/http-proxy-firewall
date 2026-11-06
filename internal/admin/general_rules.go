package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"

	"http-proxy-firewall/internal/config"

	"github.com/gofiber/fiber/v3"
)

type generalRulesSource interface {
	SetGeneralRules(config.GeneralRules) error
}

type upstreamSettingsSource interface {
	SetRequestRetryTimes(int)
}

// SetUpstreamSettings connects live proxy settings before mounting routes.
func (h *Handler) SetUpstreamSettings(source upstreamSettingsSource) { h.upstream = source }

type generalRulesSnapshot struct {
	config.GeneralRules
	Available         bool     `json:"available"`
	Overrides         []string `json:"overrides"`
	UpstreamAvailable bool     `json:"upstream_available"`
}

func (h *Handler) generalRulesSnapshot() (generalRulesSnapshot, error) {
	rules, err := h.generalFile.Read()
	if err != nil {
		return generalRulesSnapshot{}, err
	}
	result := generalRulesSnapshot{GeneralRules: rules, Available: h.general != nil, Overrides: h.generalFile.ProcessOverrides(), UpstreamAvailable: h.upstream != nil}
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
			WhitelistIPs              []string `json:"whitelist_ips"`
			WhitelistNetworks         []string `json:"whitelist_networks"`
			AllowedCountries          []string `json:"allowed_countries"`
			IPCheckpoint              *bool    `json:"ip_checkpoint"`
			CountryCheckpoint         *bool    `json:"country_checkpoint"`
			DDoSThreshold             *uint64  `json:"ddos_threshold"`
			UpstreamRequestRetryTimes *int     `json:"upstream_request_retry_times"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF || input.IPCheckpoint == nil || input.CountryCheckpoint == nil || input.DDoSThreshold == nil {
			return c.Status(400).JSON(fiber.Map{"error": "Supply whitelist lists, both checkpoint switches and a DDoS threshold as JSON"})
		}
		h.generalMu.Lock()
		defer h.generalMu.Unlock()
		// Older API clients omit this field; preserve its existing YAML value.
		previous, err := h.generalFile.Read()
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Unable to read general settings YAML"})
		}
		retries := previous.UpstreamRequestRetryTimes
		if input.UpstreamRequestRetryTimes != nil {
			if h.upstream == nil {
				return c.Status(503).JSON(fiber.Map{"error": "Upstream settings are unavailable"})
			}
			retries = *input.UpstreamRequestRetryTimes
		}
		rules, err := (config.GeneralRules{WhitelistIPs: input.WhitelistIPs, WhitelistNetworks: input.WhitelistNetworks, AllowedCountries: input.AllowedCountries, IPCheckpoint: *input.IPCheckpoint, CountryCheckpoint: *input.CountryCheckpoint, DDoSThreshold: *input.DDoSThreshold, UpstreamRequestRetryTimes: retries}).Normalize()
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
