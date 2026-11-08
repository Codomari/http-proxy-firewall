package server

import "github.com/gofiber/fiber/v3"

const statusErrorPage = `<!doctype html>
<html lang="{{LANG}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{STATUS_CODE}} — {{STATUS_TITLE}}</title>
<style>html{color-scheme:light dark;font:16px system-ui,sans-serif}body{max-width:40rem;margin:18vh auto;padding:1.5rem}p{line-height:1.6}small{opacity:.65}</style></head>
<body id="status-page" data-page="{{PAGE_TYPE}}" data-status="{{STATUS_CODE}}" data-translations="{{TRANSLATIONS}}"><style>{{LANGUAGE_STYLE}}</style><div id="status-language-picker" class="language-picker" hidden><label for="status-language" data-i18n="language_label">{{LANGUAGE_LABEL}}</label><select id="status-language">{{LANGUAGE_OPTIONS}}</select></div><small>{{STATUS_CODE}}</small><h1 data-i18n="{{STATUS_TITLE_KEY}}">{{STATUS_TITLE}}</h1><p data-i18n="{{STATUS_MESSAGE_KEY}}">{{STATUS_MESSAGE}}</p><script>{{LANGUAGE_SCRIPT}}</script></body></html>`

func (g *certificateGuard) rejectBlacklisted(c fiber.Ctx) error {
	host, err := certificateHostname(string(c.Request().Header.Host()))
	if err != nil {
		return c.Next()
	}
	now := g.now()
	g.mu.Lock()
	until := g.blacklist[host]
	blocked := until.After(now)
	if !blocked {
		delete(g.blacklist, host)
	}
	g.mu.Unlock()
	if !blocked {
		return c.Next()
	}
	country := ""
	if g.country != nil {
		country = g.country(c)
	}
	page := statusPageForCountry(country)
	if c.Request().Header.ContentLength() > 0 || len(c.Request().Header.Peek("Transfer-Encoding")) != 0 {
		c.Response().Header.SetConnectionClose()
	}
	c.Set("Cache-Control", "no-store")
	c.Set("Content-Type", "text/html; charset=utf-8")
	c.Set("Content-Language", page.language)
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Content-Security-Policy", conflictCSP)
	return c.Status(fiber.StatusConflict).SendString(page.blacklisted)
}
