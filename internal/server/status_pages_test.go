package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestStatusPagesEmbedAllLanguagesAndGame(t *testing.T) {
	t.Chdir(t.TempDir()) // Rendering cannot depend on files beside the binary.
	var catalog map[string]statusMessages
	if err := json.Unmarshal(statusMessagesJSON, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 11 {
		t.Fatalf("languages=%d want=11", len(catalog))
	}
	for _, tc := range []struct{ country, language string }{
		{"Azerbaijan", "az"}, {"United Kingdom", "en"}, {"Turkey", "tr"}, {"Türkiye", "tr"},
		{"Russian Federation", "ru"}, {"Ukraine", "uk"}, {"Germany", "de"}, {"Italy", "it"},
		{"Spain", "es"}, {"Portugal", "pt"}, {"Kazakhstan", "kk-KZ"}, {"Japan", "ja"},
		{"", "en"}, {"France", "en"}, {" AZ ", "az"},
	} {
		t.Run(tc.country, func(t *testing.T) {
			page := statusPageForCountry(tc.country)
			if page.language != tc.language {
				t.Fatalf("language=%s want=%s", page.language, tc.language)
			}
			messages := catalog[tc.language]
			fields := reflect.ValueOf(messages)
			for i := 0; i < fields.NumField(); i++ {
				if fields.Field(i).String() == "" {
					t.Fatal("empty translation")
				}
			}
			var ctx fasthttp.RequestCtx
			ctx.Request.Header.SetMethod("GET")
			serveRestarting(&ctx, tc.country)
			if string(ctx.Response.Header.Peek("Content-Language")) != tc.language {
				t.Fatal("missing Content-Language")
			}
			for _, want := range []string{`lang="` + tc.language + `"`, `id="restart-game"`, `id="game-again"`, `id="restart-continue"`, restartingJS, restartingCSS} {
				if !strings.Contains(page.restarting, want) {
					t.Fatalf("restart missing %q", want)
				}
			}
			if !strings.Contains(page.blacklisted, messages.BlockedTitle) || !strings.Contains(page.blacklisted, messages.BlockedMessage) {
				t.Fatal("blocked translations missing")
			}
			if !strings.Contains(page.tlsHostnameRequired, messages.TLSHostnameTitle) || !strings.Contains(page.tlsHostnameRequired, messages.TLSHostnameMessage) {
				t.Fatal("TLS hostname translations missing")
			}
			for _, body := range []string{page.restarting, page.blacklisted, page.tlsHostnameRequired} {
				if !strings.Contains(body, `id="status-language"`) || strings.Count(body, "<option value=") != 11 || !strings.Contains(body, statusLanguageJS) || !strings.Contains(body, statusLanguageCSS) {
					t.Fatal("embedded language selector missing")
				}
				for _, forbidden := range []string{"{{", "<script src=", "<link ", "https://", "http://"} {
					if strings.Contains(body, forbidden) {
						t.Fatalf("unexpanded template or external asset: %s", forbidden)
					}
				}
			}
			csp := string(ctx.Response.Header.Peek("Content-Security-Policy"))
			if !strings.Contains(csp, assetHash(restartingJS)) || !strings.Contains(csp, assetHash(restartingCSS)) || !strings.Contains(csp, assetHash(statusLanguageJS)) || !strings.Contains(csp, assetHash(statusLanguageCSS)) {
				t.Fatal("CSP hash mismatch")
			}
		})
	}
	if catalog["en"].Reassurance != "Do not worry (:\nWe are coming back in few seconds" {
		t.Fatal("English reassurance changed")
	}
}
