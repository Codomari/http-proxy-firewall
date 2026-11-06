package server

import (
	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/admin"
)

func (s *Server) statusTestPages() []admin.TestPage {
	return []admin.TestPage{
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
