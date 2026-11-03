package admin

import (
	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/firewall"
)

type cloudflareSource interface {
	CloudflareHosts() []firewall.CloudflareHost
	SetCloudflareHost(string, bool) error
}

type cloudflareSnapshot struct {
	Available bool                      `json:"available"`
	Hosts     []firewall.CloudflareHost `json:"hosts"`
}

func (h *Handler) cloudflareSnapshot() cloudflareSnapshot {
	result := cloudflareSnapshot{Hosts: []firewall.CloudflareHost{}}
	if h.cloudflare != nil {
		result.Available = true
		result.Hosts = h.cloudflare.CloudflareHosts()
	}
	return result
}

func adminMutationAllowed(c fiber.Ctx) bool {
	return c.Get("X-PF-Admin") == "1" && c.Get("Sec-Fetch-Site") != "cross-site" && c.Request().Header.ContentLength() == 0
}

func (h *Handler) serveCloudflare(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead:
		return c.JSON(h.cloudflareSnapshot())
	case fiber.MethodPost, fiber.MethodDelete:
		if !adminMutationAllowed(c) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Same-origin admin request without a body required"})
		}
		name, err := firewall.CanonicalHostnamePattern(c.Query("hostname"))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		value := c.Query("enabled")
		if value != "" && value != "true" && value != "false" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "enabled must be true or false"})
		}
		if h.cloudflare == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Cloudflare settings are unavailable"})
		}
		enabled := c.Method() != fiber.MethodDelete && value != "false"
		if err := h.cloudflare.SetCloudflareHost(name, enabled); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Unable to save Cloudflare settings. Check the settings file permissions, disk space and 256-rule limit."})
		}
		return c.JSON(h.cloudflareSnapshot())
	default:
		c.Set("Allow", "GET, HEAD, POST, DELETE")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
}
