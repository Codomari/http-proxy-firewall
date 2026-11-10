package proxy

import (
	"maps"

	"github.com/gofiber/fiber/v3"
)

// SetStatusPages installs response replacements before serving requests. It
// applies to every host route, before streams take ownership of monitoring and
// connections. Unregistered statuses retain the origin response.
func (h *Handler) SetStatusPages(pages map[int]fiber.Handler) {
	h.statusPages = maps.Clone(pages)
	for _, route := range h.routes {
		route.SetStatusPages(pages)
	}
}
