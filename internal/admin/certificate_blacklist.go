package admin

import (
	"net"
	"strings"
	"time"

	"http-proxy-firewall/internal/firewall"

	"github.com/gofiber/fiber/v3"
)

type CertificateBlacklistEntry struct {
	Hostname string    `json:"hostname"`
	Expires  time.Time `json:"expires"`
}

type CertificateBlacklist interface {
	CertificateBlacklistEntries() []CertificateBlacklistEntry
	RemoveCertificateBlacklistHost(string) error
}

// SetCertificateBlacklist must run before the admin routes accept requests.
func (h *Handler) SetCertificateBlacklist(source CertificateBlacklist) {
	h.certBlacklist = source
}

func (h *Handler) certificateBlacklistSnapshot() fiber.Map {
	hosts := []CertificateBlacklistEntry{}
	if h.certBlacklist != nil {
		hosts = h.certBlacklist.CertificateBlacklistEntries()
	}
	return fiber.Map{"available": h.certBlacklist != nil, "hosts": hosts}
}

func (h *Handler) serveCertificateBlacklist(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead:
		return c.JSON(h.certificateBlacklistSnapshot())
	case fiber.MethodDelete:
		if !adminMutationAllowed(c) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Same-origin admin request without a body required"})
		}
		raw := c.Query("hostname")
		host, err := firewall.CanonicalHostname(raw)
		if err != nil || net.ParseIP(host) != nil || !strings.Contains(host, ".") || strings.ContainsAny(raw, ":|*") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "A DNS hostname is required"})
		}
		if h.certBlacklist == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Certificate blacklist is unavailable"})
		}
		if err := h.certBlacklist.RemoveCertificateBlacklistHost(host); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Unable to save certificate blacklist. Check working-directory permissions and disk space."})
		}
		return c.JSON(h.certificateBlacklistSnapshot())
	default:
		c.Set("Allow", "GET, HEAD, DELETE")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
}
