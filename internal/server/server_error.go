package server

import (
	"errors"

	"github.com/gofiber/fiber/v3"
)

type serverErrorPageKey struct{}

// Handle local failures before metrics and debug capture finalize the response.
func (s *Server) serverErrorPage(c fiber.Ctx) error {
	err := c.Next()
	if c.Locals(serverErrorPageKey{}) != nil {
		return err
	}
	status := c.Response().StatusCode()
	if err != nil {
		status = fiber.StatusInternalServerError
		var ferr *fiber.Error
		if errors.As(err, &ferr) {
			status = ferr.Code
		}
	}
	switch status {
	case fiber.StatusInternalServerError, fiber.StatusBadGateway, fiber.StatusServiceUnavailable:
		return s.serveServerError(c, status)
	default:
		return err
	}
}

func (s *Server) serveServerError(c fiber.Ctx, status int) error {
	page := statusPageForCountry(s.statusCountry(c))
	var body string
	switch status {
	case fiber.StatusInternalServerError:
		body = page.serverError
	case fiber.StatusBadGateway:
		body = page.badGateway
	case fiber.StatusServiceUnavailable:
		body = page.unavailable
	}
	// Origin representation headers (encoding, length, validators, CSP, etc.)
	// describe the discarded body. Retain retry guidance and request close state.
	retryAfter := string(c.Response().Header.Peek("Retry-After"))
	closeConnection := c.Response().ConnectionClose()
	c.Response().Reset()
	if retryAfter != "" {
		c.Set("Retry-After", retryAfter)
	}
	if closeConnection {
		c.Response().Header.SetConnectionClose()
	}
	c.Locals(serverErrorPageKey{}, true)
	c.Set("Cache-Control", "no-store")
	c.Set("Content-Language", page.language)
	c.Set("Content-Security-Policy", conflictCSP)
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Status(status).Type("html", "utf-8").SendString(body)
}
