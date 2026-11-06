package admin

import (
	"time"

	"github.com/gofiber/fiber/v3"
)

type CertificateEntry struct {
	Hostname  string    `json:"hostname"`
	Names     []string  `json:"names"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	Expires   time.Time `json:"expires"`
	Source    string    `json:"source"`
}

type CertificateRequest struct {
	Hostname string     `json:"hostname"`
	Status   string     `json:"status"`
	Message  string     `json:"message,omitempty"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
}

type CertificateService interface {
	CertificateEntries() ([]CertificateEntry, error)
	CertificateRequests() []CertificateRequest
	RequestCertificate(string) error
	CanRequestCertificate() bool
}

func (h *Handler) SetCertificateService(source CertificateService) { h.certificates = source }

func (h *Handler) certificateSnapshot() (fiber.Map, error) {
	entries := []CertificateEntry{}
	requests := []CertificateRequest{}
	manual := false
	if h.certificates != nil {
		var err error
		entries, err = h.certificates.CertificateEntries()
		if err != nil {
			return nil, err
		}
		requests = h.certificates.CertificateRequests()
		manual = h.certificates.CanRequestCertificate()
	}
	return fiber.Map{"certificates": entries, "requests": requests, "manual_available": manual}, nil
}

func (h *Handler) serveCertificates(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead:
		data, err := h.certificateSnapshot()
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"error": "Unable to read certificate metadata"})
		}
		return c.JSON(data)
	case fiber.MethodPost:
		if !adminMutationAllowed(c) {
			return c.Status(403).JSON(fiber.Map{"error": "Same-origin admin request without a body required"})
		}
		if h.certificates == nil || !h.certificates.CanRequestCertificate() {
			return c.Status(503).JSON(fiber.Map{"error": "Manual requests require automatic TLS certificates to be enabled"})
		}
		if err := h.certificates.RequestCertificate(c.Query("hostname")); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(202).JSON(fiber.Map{"message": "Certificate request started. Status will update below."})
	default:
		c.Set("Allow", "GET, HEAD, POST")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
}
