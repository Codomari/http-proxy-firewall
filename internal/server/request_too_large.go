package server

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) serveRequestTooLarge(c fiber.Ctx, limit int64, inputLimit bool) error {
	page := statusPageForCountry(s.statusCountry(c))
	body := page.requestTooLarge
	if inputLimit {
		body = page.inputTooLarge
	}
	// Replace the limit in the initial message and every embedded translation.
	body = strings.ReplaceAll(body, "{limit}", formatBodyLimit(limit))
	c.Set("Cache-Control", "no-store")
	c.Set("Content-Language", page.language)
	c.Set("Content-Security-Policy", conflictCSP)
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Status(fiber.StatusRequestEntityTooLarge).Type("html", "utf-8").SendString(body)
}

func formatBodyLimit(limit int64) string {
	if limit%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", limit>>20)
	}
	if limit%(1<<10) == 0 {
		return fmt.Sprintf("%d KiB", limit>>10)
	}
	return fmt.Sprintf("%d B", limit)
}
