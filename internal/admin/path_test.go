package admin

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"
)

func TestCustomAdminURIProtectsRoutesAndRewritesAssets(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin = config.Admin{Enabled: true, URI: "ops/control", User: "test-admin", Password: "test-password:with-colon"}
	registry := monitoring.New(cfg)
	handler, err := New(cfg, registry, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	handler.Mount(app)
	app.Use(registry.Middleware(func(host string) (string, error) { return host, nil }))
	app.Use(func(c fiber.Ctx) error { return c.SendString("upstream reached") })
	for _, suffix := range []string{"", "/assets/admin.css", "/assets/admin.js", "/assets/favicon.svg", "/api/overview", "/api/hosts", "/api/runtime"} {
		path := "/ops/control" + suffix
		if resp := request(t, app, http.MethodGet, path, ""); resp.StatusCode != 401 {
			t.Fatalf("custom admin route not protected: %s", path)
		}
		resp := request(t, app, http.MethodGet, path, validBasic())
		if resp.StatusCode != 200 {
			t.Fatalf("custom admin route unavailable: %s", path)
		}
		if suffix == "" || suffix == "/assets/admin.js" {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), BasePath) || !strings.Contains(string(body), "/ops/control") {
				t.Fatalf("asset URLs or polling base were not rewritten: %s", path)
			}
		}
	}
	for _, path := range []string{"/OPS/CONTROL/api/hosts", "/ops/%63ontrol/api/overview", "/ops/control/../control/api/runtime", "//ops//control/api/hosts"} {
		if resp := request(t, app, http.MethodGet, path, ""); resp.StatusCode != 401 {
			t.Fatalf("custom reserved path bypassed auth: %s", path)
		}
	}
	if registry.Totals().Requests != 0 {
		t.Fatal("custom admin traffic entered monitoring totals")
	}
	resp := request(t, app, http.MethodGet, BasePath, "")
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "upstream reached" {
		t.Fatal("default admin URL remained active after changing PF_ADMIN_URI")
	}
}
