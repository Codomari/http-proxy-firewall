package observability

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestMetricsHaveBoundedLabelsAndCountHandlerErrors(t *testing.T) {
	app := fiber.New(fiber.Config{RequestMethods: append(append([]string(nil), fiber.DefaultMethods...), "CUSTOM")})
	monitor := New()
	monitor.Mount(app)
	app.Use(monitor.Handler)
	app.Use(func(c fiber.Ctx) error {
		if strings.Contains(c.OriginalURL(), "fail") {
			return errors.New("private error details")
		}
		return c.SendStatus(204)
	})
	for _, request := range []struct{ method, path string }{{"GET", "/one?private=value"}, {"CUSTOM", "/random/id"}, {"GET", "/fail"}} {
		response, err := app.Test(httptest.NewRequest(request.method, request.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	response, err := app.Test(httptest.NewRequest("GET", MetricsPath, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, expected := range []string{`proxy_requests_total{method="GET",status="204"} 1`, `proxy_requests_total{method="GET",status="500"} 1`, `proxy_requests_total{method="OTHER",status="204"} 1`} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing metric %s", expected)
		}
	}
	for _, sensitive := range []string{"private=value", "/random/id", "private error details", `path="`} {
		if strings.Contains(text, sensitive) {
			t.Errorf("unbounded or private metric label: %q", sensitive)
		}
	}
}
