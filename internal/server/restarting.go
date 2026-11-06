package server

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"time"

	"http-proxy-firewall/internal/config"

	"github.com/valyala/fasthttp"
)

const (
	statusServerRestarting = 540
	restartNoticePeriod    = 3 * time.Second
)

//go:embed assets/restarting.html
var restartingHTML string

//go:embed assets/restarting.css
var restartingCSS string

//go:embed assets/restarting.js
var restartingJS string

var restartingCSP = "default-src 'none'; style-src '" + assetHash(restartingCSS) + "' '" + assetHash(statusLanguageCSS) + "'; script-src '" + assetHash(restartingJS) + "' '" + assetHash(statusLanguageJS) + "'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var conflictCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src '" + assetHash(statusLanguageJS) + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func assetHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func serveRestarting(ctx *fasthttp.RequestCtx, country string) {
	page := statusPageForCountry(country)
	ctx.Response.Reset()
	ctx.Response.SetStatusCode(statusServerRestarting)
	ctx.Response.Header.SetStatusMessage([]byte("Server Restarting"))
	ctx.Response.Header.SetServer(config.ServerName)
	ctx.Response.Header.SetContentType("text/html; charset=utf-8")
	ctx.Response.Header.Set("Content-Language", page.language)
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Content-Security-Policy", restartingCSP)
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("Referrer-Policy", "no-referrer")
	ctx.Response.Header.SetConnectionClose()
	ctx.Response.SetBodyString(page.restarting)
	ctx.Response.SkipBody = ctx.Request.Header.IsHead()
}

// Give incoming requests a chance to receive the restart screen before closing
// listeners. Reserve most of a shorter stop deadline for draining active work.
func waitForRestartNotice(ctx context.Context) {
	notice := restartNoticePeriod
	if deadline, ok := ctx.Deadline(); ok {
		notice = min(notice, time.Until(deadline)/10)
	}
	if notice <= 0 {
		return
	}
	timer := time.NewTimer(notice)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
