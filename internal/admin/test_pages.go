package admin

import (
	"html"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// TestPage registers a harmless, authenticated preview of a public status page.
// Register new previews before mounting the admin routes.
type TestPage struct {
	Name    string        `json:"name"`
	Title   string        `json:"title"`
	Status  int           `json:"status"`
	Handler fiber.Handler `json:"-"`
}

func (h *Handler) SetTestPages(pages []TestPage) { h.testPages = append([]TestPage(nil), pages...) }

func (h *Handler) serveTestPage(c fiber.Ctx, path string) error {
	if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead {
		c.Set("Allow", "GET, HEAD")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
	if path == h.basePath+"/api/test-pages" {
		pages := h.testPages
		if pages == nil {
			pages = []TestPage{}
		}
		return c.JSON(fiber.Map{"pages": pages})
	}
	base := h.basePath + "/test/pages"
	if path == base || path == base+"/" {
		var links strings.Builder
		for _, page := range h.testPages {
			links.WriteString(`<li><a href="` + html.EscapeString(base+"/"+page.Name) + `">` + html.EscapeString(page.Title) + `</a></li>`)
		}
		return c.Type("html").SendString(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Test pages</title><h1>Test pages</h1><p>Authenticated previews; these do not change the server state.</p><ul>` + links.String() + `</ul></html>`)
	}
	name := strings.TrimPrefix(path, base+"/")
	for _, page := range h.testPages {
		if page.Name == name {
			return page.Handler(c)
		}
	}
	return c.SendStatus(fiber.StatusNotFound)
}
