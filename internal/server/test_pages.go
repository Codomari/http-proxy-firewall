package server

import (
	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/admin"
)

func (s *Server) statusTestPages() []admin.TestPage {
	return []admin.TestPage{
		{Name: "server-error", Title: "Internal Server Error", Status: fiber.StatusInternalServerError, Handler: func(c fiber.Ctx) error {
			return s.serveServerError(c, fiber.StatusInternalServerError)
		}},
		{Name: "bad-gateway", Title: "Bad Gateway", Status: fiber.StatusBadGateway, Handler: func(c fiber.Ctx) error {
			return s.serveServerError(c, fiber.StatusBadGateway)
		}},
		{Name: "service-unavailable", Title: "Service Unavailable", Status: fiber.StatusServiceUnavailable, Handler: func(c fiber.Ctx) error {
			return s.serveServerError(c, fiber.StatusServiceUnavailable)
		}},
		{Name: "request-too-large", Title: "Request Entity Too Large", Status: fiber.StatusRequestEntityTooLarge, Handler: func(c fiber.Ctx) error {
			return s.serveRequestTooLarge(c, s.bodyLimit(), false)
		}},
		{Name: "restart", Title: "Server restarting", Status: statusServerRestarting, Handler: func(c fiber.Ctx) error {
			serveRestarting(c.RequestCtx(), s.statusCountry(c))
			return nil
		}},
		{Name: "blocked-hostname", Title: "Hostname blacklisted", Status: fiber.StatusConflict, Handler: func(c fiber.Ctx) error {
			page := statusPageForCountry(s.statusCountry(c))
			c.Set("Content-Language", page.language)
			c.Set("Content-Security-Policy", conflictCSP)
			return c.Status(fiber.StatusConflict).Type("html").SendString(page.blacklisted)
		}},
		{Name: "tls-hostname", Title: "TLS hostname required", Status: fiber.StatusConflict, Handler: func(c fiber.Ctx) error {
			serveTLSHostnameRequired(c.RequestCtx(), s.statusCountry(c))
			return nil
		}},
	}
}
