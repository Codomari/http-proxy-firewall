package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/intelligence"
	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/proxy"
	"http-proxy-firewall/internal/storage"
)

type testPenalties struct{ until time.Time }

func (p testPenalties) DDoSState(host string) (bool, time.Time) {
	return host == "alpha.example", p.until
}

func adminTestApp(t *testing.T, enabled bool) (*fiber.App, *monitoring.Registry) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Admin = config.Admin{Enabled: enabled, User: "test-admin", Password: "test-password:with-colon", MaxHosts: 2000}
	registry := monitoring.New(cfg)
	h, err := New(cfg, registry, testPenalties{until: time.Now().Add(time.Minute)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	h.Mount(app)
	app.Use(registry.Middleware(func(host string) (string, error) { return strings.ToLower(host), nil }))
	app.Use(func(c fiber.Ctx) error { return c.SendString("upstream reached") })
	return app, registry
}

func request(t *testing.T, app *fiber.App, method, path, auth string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "http://admin.example"+path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
func validBasic() string { return basic("test-admin", "test-password:with-colon") }

func TestEveryAdminResourceRequiresAuthAndSecurityHeaders(t *testing.T) {
	app, registry := adminTestApp(t, true)
	for _, path := range []string{BasePath, BasePath + "/", BasePath + "/assets/admin.css", BasePath + "/assets/admin.js", BasePath + "/assets/favicon.svg", BasePath + "/api/overview", BasePath + "/api/hosts", BasePath + "/api/runtime", BasePath + "/unknown"} {
		for _, auth := range []string{"", "Bearer invalid", "Basic ???", basic("wrong", "test-password:with-colon"), basic("test-admin", "wrong")} {
			resp := request(t, app, http.MethodGet, path, auth)
			if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
				t.Fatalf("%s auth status=%d", path, resp.StatusCode)
			}
			if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing security headers")
			}
			if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("missing frame policy")
			}
		}
	}
	if registry.Totals().Requests != 0 {
		t.Fatal("admin requests entered traffic totals")
	}
}

func TestEmbeddedAssetsHaveCorrectTypesAndNoCredentials(t *testing.T) {
	app, _ := adminTestApp(t, true)
	for _, asset := range []struct{ path, media, marker string }{{BasePath, "text/html", "Proxy firewall"}, {BasePath + "/assets/admin.css", "text/css", ":root"}, {BasePath + "/assets/admin.js", "text/javascript", "textContent"}, {BasePath + "/assets/favicon.svg", "image/svg+xml", "<svg"}} {
		resp := request(t, app, http.MethodGet, asset.path, validBasic())
		if resp.StatusCode != 200 {
			t.Fatalf("%s status=%d", asset.path, resp.StatusCode)
		}
		media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || media != asset.media {
			t.Fatalf("content type: %s", resp.Header.Get("Content-Type"))
		}
		data, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(data), asset.marker) || strings.Contains(string(data), "test-password") || strings.Contains(string(data), "test-admin") {
			t.Fatal("asset missing or credentials reflected")
		}
	}
	js, _ := embedded.ReadFile("assets/admin.js")
	for _, unsafe := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if strings.Contains(string(js), unsafe) {
			t.Fatalf("unsafe host rendering primitive %s", unsafe)
		}
	}
	html, _ := embedded.ReadFile("assets/admin.html")
	if strings.Contains(string(html), "https://") || strings.Contains(string(html), "http://") || strings.Contains(string(html), "<style") {
		t.Fatal("dashboard requires external or inline assets")
	}
}

func TestDisabledAdminOwnsSubtreeAndNormalizedVariants(t *testing.T) {
	app, registry := adminTestApp(t, false)
	for _, path := range []string{BasePath, BasePath + "/api/overview", "/__pf/%5f%5fadmin/api/hosts", "/__PF/__ADMIN/assets/admin.js", "//__pf//__admin/api/runtime", "/__pf/__admin/../__admin/api/hosts", "/__pf/%255f%255fadmin/api/hosts"} {
		resp := request(t, app, http.MethodGet, path, validBasic())
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 404 || strings.Contains(string(data), "upstream reached") {
			t.Fatalf("disabled route escaped: %s status=%d", path, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Fatal("disabled admin challenged credentials")
		}
	}
	if registry.Totals().Requests != 0 {
		t.Fatal("disabled admin requests entered totals")
	}
	resp := request(t, app, http.MethodGet, "/__pf/__admin-other", "")
	if resp.StatusCode != 200 {
		t.Fatal("neighboring route accidentally reserved")
	}
}

func TestOverviewAllHostsSearchAndPenaltyData(t *testing.T) {
	app, registry := adminTestApp(t, true)
	for _, host := range []string{"alpha.example", "beta.example", "gamma.example"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/normal", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	resp := request(t, app, http.MethodGet, BasePath+"/api/overview?limit=1", validBasic())
	var overview struct {
		Hosts     []hostRow                  `json:"hosts"`
		HostCount int                        `json:"host_count"`
		Totals    monitoring.TotalsSnapshot  `json:"totals"`
		Runtime   monitoring.RuntimeSnapshot `json:"runtime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&overview); err != nil {
		t.Fatal(err)
	}
	if overview.Totals.Requests != 3 || overview.HostCount != 3 || len(overview.Hosts) != 3 || overview.Runtime.Goroutines <= 0 {
		t.Fatalf("bad overview: %+v", overview)
	}
	if overview.Hosts[0].Hostname != "alpha.example" || !overview.Hosts[0].DDoS || overview.Hosts[0].DDoSUntil == nil {
		t.Fatal("penalty state missing")
	}
	resp = request(t, app, http.MethodGet, BasePath+"/api/hosts?limit=999999&search=BETA", validBasic())
	var page hostsList
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Hosts) != 1 || page.Hosts[0].Hostname != "beta.example" {
		t.Fatalf("bad search: %+v", page)
	}
	resp = request(t, app, http.MethodGet, BasePath+"/api/hosts?offset=100", validBasic())
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Hosts) != 3 || page.Total != 3 {
		t.Fatal("legacy pagination parameters hid tracked hosts")
	}
	if registry.Totals().Requests != 3 {
		t.Fatal("API polling entered traffic totals")
	}
}

func TestBoundedQueriesMethodsAndDisabledConstruction(t *testing.T) {
	app, _ := adminTestApp(t, true)
	for _, query := range []string{"search=" + strings.Repeat("x", 257)} {
		resp := request(t, app, http.MethodGet, BasePath+"/api/hosts?"+query, validBasic())
		if resp.StatusCode != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	resp := request(t, app, http.MethodPost, BasePath+"/api/overview", validBasic())
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatal("unsupported admin method not rejected")
	}
	if _, err := New(config.Config{}, nil, nil, nil); err != nil {
		t.Fatal("disabled constructor requires live dependencies")
	}
	cfg := config.Config{Admin: config.Admin{Enabled: true}}
	if _, err := New(cfg, nil, nil, nil); err == nil {
		t.Fatal("enabled admin accepted missing credentials")
	}
}

func TestHostListIncludesMoreThanOneThousandHosts(t *testing.T) {
	app, registry := adminTestApp(t, true)
	handler := app.Handler()
	const count = 1205
	for i := 0; i < count; i++ {
		ctx := new(fasthttp.RequestCtx)
		ctx.Init(new(fasthttp.Request), nil, nil)
		ctx.Request.Header.SetHost(fmt.Sprintf("host-%04d.example", i))
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/")
		handler(ctx)
	}
	resp := request(t, app, http.MethodGet, BasePath+"/api/hosts?limit=1&offset=99999", validBasic())
	var list hostsList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Hosts) != count || list.Total != count || registry.Totals().Requests != count {
		t.Fatalf("host list was paginated or affected traffic totals: returned=%d total=%d", len(list.Hosts), list.Total)
	}
}

type testRedisStatus struct{ snapshot storage.Snapshot }

func (s testRedisStatus) Snapshot() storage.Snapshot { return s.snapshot }

type testDatabaseStatus struct{ snapshot intelligence.DatabaseSnapshot }

func (s testDatabaseStatus) DatabaseStatus() intelligence.DatabaseSnapshot { return s.snapshot }

func TestOverviewIncludesStorageAndDatabaseStatus(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin = config.Admin{Enabled: true, User: "test-admin", Password: "test-password:with-colon"}
	cfg.Redis.Password, cfg.Intelligence.MaxMindLicenseKey = "private-redis-password", "private-maxmind-key"
	modified := time.Date(2026, 10, 31, 12, 30, 0, 0, time.UTC)
	sources := ServiceSources{
		Redis:   testRedisStatus{storage.Snapshot{Enabled: true, Status: "available", Reads: 42, Writes: 17}},
		MaxMind: testDatabaseStatus{intelligence.DatabaseSnapshot{Loaded: true, FileExists: true, LastModified: &modified, AutoUpdateEnabled: true}},
	}
	h, err := New(cfg, monitoring.New(cfg), nil, nil, sources)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	h.Mount(app)
	resp := request(t, app, http.MethodGet, BasePath+"/api/overview", validBasic())
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var overview struct {
		Services serviceSnapshot `json:"services"`
	}
	if err := json.Unmarshal(data, &overview); err != nil {
		t.Fatal(err)
	}
	if !overview.Services.Redis.Enabled || overview.Services.Redis.Reads != 42 || overview.Services.Redis.Writes != 17 || !overview.Services.MaxMind.Loaded || overview.Services.MaxMind.LastModified == nil || !overview.Services.MaxMind.LastModified.Equal(modified) {
		t.Fatalf("missing service telemetry: %+v", overview.Services)
	}
	if strings.Contains(string(data), "private-redis-password") || strings.Contains(string(data), "private-maxmind-key") {
		t.Fatal("service telemetry exposed deployment credentials")
	}
}

func TestOnlyConfiguredAdminAuthorizationIsRemovedFromBackendRoutes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Admin = config.Admin{Enabled: enabled, User: "test-admin", Password: "test-password:with-colon"}
		h, err := New(cfg, monitoring.New(cfg), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		app := fiber.New()
		h.Mount(app)
		app.Use(func(c fiber.Ctx) error {
			values := c.Request().Header.PeekAll("Authorization")
			result := make([]string, 0, len(values))
			for _, value := range values {
				result = append(result, string(value))
			}
			return c.JSON(result)
		})
		backend := basic("test-admin", "different-backend-password")
		for _, testcase := range []struct{ values, want []string }{
			{[]string{validBasic()}, []string{}},
			{[]string{"Bearer backend-token", validBasic(), backend, "Bearer backend-token", validBasic()}, []string{"Bearer backend-token", backend, "Bearer backend-token"}},
			{[]string{backend, backend}, []string{backend, backend}},
		} {
			req := httptest.NewRequest(http.MethodGet, "http://backend.example/__pf/other", nil)
			for _, value := range testcase.values {
				req.Header.Add("Authorization", value)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			err = json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
			if err != nil || !reflect.DeepEqual(got, testcase.want) {
				t.Fatalf("enabled=%v auth values=%q, want%q, err=%v", enabled, got, testcase.want, err)
			}
		}
	}
	// The default empty credential hashes must never match an empty Basic pair.
	h, err := New(config.Config{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	h.Mount(app)
	app.Use(func(c fiber.Ctx) error { return c.SendString(c.Get("Authorization")) })
	resp := request(t, app, http.MethodGet, "/normal", basic("", ""))
	data, _ := io.ReadAll(resp.Body)
	if string(data) != basic("", "") {
		t.Fatal("unconfigured empty credentials were stripped")
	}
}

func TestMatchingAdminCredentialsNeverReachActualProxyUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewEncoder(w).Encode(req.Header.Values("Authorization"))
	}))
	defer upstream.Close()
	cfg := config.Defaults()
	cfg.Proxy.Upstream, cfg.Proxy.IPv4Redirect = upstream.URL, ""
	cfg.Admin = config.Admin{Enabled: false, User: "test-admin", Password: "test-password:with-colon"}
	h, err := New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	forward, err := proxy.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	app := fiber.New()
	h.Mount(app)
	app.Use(forward.Handle)
	req := httptest.NewRequest(http.MethodGet, "http://service.example/__pf/sibling", nil)
	for _, value := range []string{"Bearer backend-token", validBasic(), "Bearer backend-token", validBasic()} {
		req.Header.Add("Authorization", value)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var actual []string
	if err := json.NewDecoder(resp.Body).Decode(&actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, []string{"Bearer backend-token", "Bearer backend-token"}) {
		t.Fatalf("upstream received wrong Authorization values: %q", actual)
	}
}

func TestAdminBodyResponsesCloseWithoutKeepingUploadsAlive(t *testing.T) {
	app, _ := adminTestApp(t, true)
	for _, auth := range []string{"", validBasic()} {
		req := httptest.NewRequest(http.MethodPost, "http://admin.example"+BasePath, strings.NewReader("unconsumed upload"))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 401
		if auth != "" {
			want = 405
		}
		if resp.StatusCode != want || !resp.Close {
			t.Fatalf("status=%d close=%v", resp.StatusCode, resp.Close)
		}
	}
	// Fiber's net/http test adapter emits an invalid Content-Length:-1 for a
	// chunked request, so inspect that request-header state directly instead.
	var raw fasthttp.RequestCtx
	raw.Request.Header.SetMethod(http.MethodPost)
	raw.Request.Header.SetContentLength(-1)
	c := app.AcquireCtx(&raw)
	defer app.ReleaseCtx(c)
	h := &Handler{enabled: true}
	if err := h.serve(c, BasePath); err != nil {
		t.Fatal(err)
	}
	if !raw.Response.Header.ConnectionClose() {
		t.Fatal("chunked admin request kept its connection alive")
	}
}
