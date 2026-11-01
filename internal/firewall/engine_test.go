package firewall

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/config"
	cve2026109618 "http-proxy-firewall/internal/firewall/cves/2026-109618"
	"http-proxy-firewall/internal/session"
)

func testConfig() config.Config {
	return config.Config{Firewall: config.Firewall{
		MaxBodyBytes: 1024, MaxBufferedBytes: 4096, CacheCapacity: 32,
		RequestThreshold: 200, SamplingWindow: 10 * time.Second, PenaltyLifetime: time.Minute,
	}}
}

type fakeIntelligence struct {
	country string
	google  bool
}

func (f fakeIntelligence) Country(context.Context, netip.Addr) string { return f.country }
func (f fakeIntelligence) IsGoogleBot(netip.Addr) bool                { return f.google }

func testEngine(t *testing.T, cfg config.Config, intelligence Intelligence) *Engine {
	t.Helper()
	e, err := New(cfg, intelligence, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func testApp(e *Engine, next fiber.Handler) *fiber.App {
	app := fiber.New(fiber.Config{BodyLimit: int(e.limits.MaxBodyBytes), StreamRequestBody: true, DisablePreParseMultipartForm: true})
	app.Use(e.Handler)
	if next == nil {
		next = func(c fiber.Ctx) error { return c.Send(bytes.Clone(c.Request().Body())) }
	}
	app.Use(next)
	return app
}

func rawRequest(method, target, contentType string, body []byte, chunked bool, extra string) string {
	var raw strings.Builder
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\nHost: example.test\r\n", method, target)
	if contentType != "" {
		fmt.Fprintf(&raw, "Content-Type: %s\r\n", contentType)
	}
	raw.WriteString(extra)
	if chunked {
		raw.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		if len(body) > 0 {
			fmt.Fprintf(&raw, "%x\r\n%s\r\n", len(body), body)
		}
		raw.WriteString("0\r\n\r\n")
	} else {
		fmt.Fprintf(&raw, "Content-Length: %d\r\n\r\n%s", len(body), body)
	}
	return raw.String()
}

// Real fasthttp header/body parsers preserve raw duplicates and decode chunking.
// Direct invocation avoids socket timing when testing ownership and overload.
func rawContext(raw string, limit int, peer string) (*fasthttp.RequestCtx, error) {
	ctx := new(fasthttp.RequestCtx)
	ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP(peer), Port: 1234}, nil)
	reader := bufio.NewReader(strings.NewReader(raw))
	if err := ctx.Request.Header.Read(reader); err != nil {
		return nil, err
	}
	if err := ctx.Request.ContinueReadBodyStream(reader, limit, false); err != nil {
		return nil, err
	}
	return ctx, nil
}

func serve(t *testing.T, app *fiber.App, e *Engine, raw string, peer string) *fasthttp.RequestCtx {
	t.Helper()
	ctx, err := rawContext(raw, int(e.limits.MaxBodyBytes), peer)
	if err != nil {
		t.Fatal(err)
	}
	app.Handler()(ctx)
	return ctx
}

func uploadBody(t *testing.T, names []string, file string) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.SetBoundary("test-boundary"); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := w.WriteField(name, "value"); err != nil {
			t.Fatal(err)
		}
	}
	if file != "" {
		part, err := w.CreateFormFile(file, "x.txt")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte("\x00\xff\r\nfile"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), w.FormDataContentType()
}

func TestBodyBytesAndFramingPreserved(t *testing.T) {
	form, formType := uploadBody(t, []string{"title", "title"}, "file")
	tests := []struct {
		name, contentType string
		body              []byte
	}{
		{"multipart", formType, form},
		{"json", "application/json", []byte(`{"x":"PHP_SESSION_UPLOAD_PROGRESS"}`)},
		{"urlencoded", "application/x-www-form-urlencoded", []byte("title=one&title=two")},
		{"binary", "application/octet-stream", []byte("\x00\xff\r\n")},
	}
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		for _, tt := range tests {
			for _, chunked := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/chunked=%t", method, tt.name, chunked), func(t *testing.T) {
					e := testEngine(t, testConfig(), nil)
					app := testApp(e, func(c fiber.Ctx) error {
						if c.Request().IsBodyStream() || c.Request().Header.ContentLength() != len(tt.body) || len(c.Request().Header.Peek("Transfer-Encoding")) != 0 {
							t.Error("upstream framing is not canonical")
						}
						return c.Send(bytes.Clone(c.Request().Body()))
					})
					ctx := serve(t, app, e, rawRequest(method, "/upload", tt.contentType, tt.body, chunked, ""), "198.51.100.1")
					if ctx.Response.StatusCode() != 200 || !bytes.Equal(ctx.Response.Body(), tt.body) {
						t.Fatalf("status=%d body=%q", ctx.Response.StatusCode(), ctx.Response.Body())
					}
					if e.budget.used.Load() != 0 {
						t.Fatal("body budget leaked")
					}
				})
			}
		}
	}
}

func TestRejectionsPrecedeEveryBypass(t *testing.T) {
	badBody, contentType := uploadBody(t, []string{"PHP_SESSION_UPLOAD_PROGRESS"}, "")
	tests := []struct {
		name, target string
		cfg          config.Config
		intel        Intelligence
		extra        string
	}{
		{"ordinary", "/", testConfig(), nil, ""},
		{"static", "/assets/file.css", testConfig(), nil, ""},
		{"google range", "/", testConfig(), fakeIntelligence{google: true}, ""},
		{"bot user agent", "/", testConfig(), nil, "User-Agent: Googlebot\r\n"},
	}
	white := testConfig()
	white.Firewall.WhitelistIPs = []string{"198.51.100.1"}
	tests = append(tests, struct {
		name, target string
		cfg          config.Config
		intel        Intelligence
		extra        string
	}{"whitelisted", "/", white, nil, ""})
	country := testConfig()
	country.Firewall.AllowedCountries = []string{" turkey "}
	tests = append(tests, struct {
		name, target string
		cfg          config.Config
		intel        Intelligence
		extra        string
	}{"country", "/", country, fakeIntelligence{country: "Turkey"}, ""})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEngine(t, tt.cfg, tt.intel)
			called := false
			app := testApp(e, func(c fiber.Ctx) error { called = true; return c.SendStatus(200) })
			ctx := serve(t, app, e, rawRequest("POST", tt.target, contentType, badBody, true, tt.extra), "198.51.100.1")
			if ctx.Response.StatusCode() != 403 || called {
				t.Fatalf("bypass skipped body policy: status=%d forwarded=%t", ctx.Response.StatusCode(), called)
			}
		})
	}
}

func TestBodyLimitsMethodsHeadersAndEncodings(t *testing.T) {
	tests := []struct {
		name, method, ct, extra string
		body                    []byte
		chunked                 bool
		limit                   int64
		want                    int
	}{
		{"known oversized", "POST", "application/json", "", bytes.Repeat([]byte("x"), 65), false, 64, 413},
		{"chunked oversized", "POST", "application/json", "", bytes.Repeat([]byte("x"), 65), true, 64, 413},
		{"exact limit", "POST", "application/json", "", bytes.Repeat([]byte("x"), 64), true, 64, 200},
		{"duplicate content type", "POST", "application/json", "Content-Type: text/plain\r\n", []byte("x"), true, 64, 400},
		{"gzip", "POST", "application/json", "Content-Encoding: gzip\r\n", []byte("x"), true, 64, 415},
		{"multiple encodings", "POST", "application/json", "Content-Encoding: gzip\r\nContent-Encoding: identity\r\n", []byte("x"), true, 64, 415},
		{"identity", "POST", "application/json", "Content-Encoding: identity\r\n", []byte("x"), true, 64, 200},
		{"malformed content type", "POST", "multipart/form-data; boundary=\"", "", []byte("x"), true, 64, 400},
		{"nested multipart", "POST", "multipart/mixed; boundary=x", "", []byte("x"), true, 64, 400},
	}
	for _, method := range []string{"GET", "HEAD", "DELETE", "OPTIONS"} {
		for _, chunked := range []bool{false, true} {
			tests = append(tests, struct {
				name, method, ct, extra string
				body                    []byte
				chunked                 bool
				limit                   int64
				want                    int
			}{fmt.Sprintf("%s-body/%t", method, chunked), method, "", "", []byte("x"), chunked, 64, 400})
			tests = append(tests, struct {
				name, method, ct, extra string
				body                    []byte
				chunked                 bool
				limit                   int64
				want                    int
			}{fmt.Sprintf("%s-empty/%t", method, chunked), method, "", "", nil, chunked, 64, 200})
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Firewall.MaxBodyBytes = tt.limit
			e := testEngine(t, cfg, nil)
			called := false
			app := testApp(e, func(c fiber.Ctx) error { called = true; return c.Send(bytes.Clone(c.Request().Body())) })
			ctx := serve(t, app, e, rawRequest(tt.method, "/", tt.ct, tt.body, tt.chunked, tt.extra), "198.51.100.1")
			if got := ctx.Response.StatusCode(); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
			if tt.want >= 400 && called {
				t.Fatal("rejected request forwarded")
			}
			if e.budget.used.Load() != 0 {
				t.Fatal("body budget leaked")
			}
		})
	}
}

func TestMultipartCanonicalBoundaryAndFileField(t *testing.T) {
	body, ct := uploadBody(t, nil, "PHP_SESSION_UPLOAD_PROGRESS")
	e := testEngine(t, testConfig(), nil)
	app := testApp(e, func(c fiber.Ctx) error {
		if string(c.Request().Header.ContentType()) != ct {
			t.Errorf("boundary not canonical: %s", c.Request().Header.ContentType())
		}
		return c.Send(bytes.Clone(c.Request().Body()))
	})
	ctx := serve(t, app, e, rawRequest("POST", "/", ct+"; badboundary=decoy", body, true, ""), "198.51.100.1")
	if ctx.Response.StatusCode() != 200 || !bytes.Equal(ctx.Response.Body(), body) {
		t.Fatal("file field rejected or body changed")
	}
}

func TestBotQueryBlockAppliesToWhitelistedClients(t *testing.T) {
	for _, key := range sensitiveQueryKeys {
		t.Run(key, func(t *testing.T) {
			e := testEngine(t, testConfig(), nil)
			ctx := serve(t, testApp(e, nil), e, rawRequest("GET", "/file.css?"+key+"=", "", nil, false, "User-Agent: YandexAdNet\r\n"), "127.0.0.1")
			if ctx.Response.StatusCode() != 403 {
				t.Fatal("bot query bypassed via static or whitelist")
			}
		})
	}
	e := testEngine(t, testConfig(), nil)
	ctx := serve(t, testApp(e, nil), e, rawRequest("GET", "/?%74oken=value", "", nil, false, "User-Agent: Googlebot\r\n"), "127.0.0.1")
	if ctx.Response.StatusCode() != 403 {
		t.Fatal("decoded query key was missed")
	}
}

func TestTrustedClientIdentity(t *testing.T) {
	tests := []struct {
		name, peer, headers string
		trusted             []string
		cf                  bool
		want                string
	}{
		{"direct spoof", "198.51.100.1", "X-Forwarded-For: 127.0.0.1\r\nCF-Connecting-IP: 127.0.0.1\r\n", nil, true, "198.51.100.1"},
		{"trusted chain", "10.0.0.2", "X-Forwarded-For: 127.0.0.1, 198.51.100.3, 10.0.0.4\r\n", []string{"10.0.0.0/8"}, false, "198.51.100.3"},
		{"trusted cloudflare", "10.0.0.2", "CF-Connecting-IP: 2001:db8::1\r\n", []string{"10.0.0.0/8"}, true, "2001:db8::1"},
		{"cloudflare disabled", "10.0.0.2", "CF-Connecting-IP: 2001:db8::1\r\n", []string{"10.0.0.0/8"}, false, "10.0.0.2"},
		{"invalid trusted chain", "10.0.0.2", "X-Forwarded-For: invalid\r\n", []string{"10.0.0.0/8"}, false, "10.0.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Firewall.TrustedProxies = tt.trusted
			cfg.Firewall.TrustCloudflareHeader = tt.cf
			e := testEngine(t, cfg, nil)
			observed := ""
			app := testApp(e, func(c fiber.Ctx) error { observed = ClientIP(c); return c.SendStatus(200) })
			serve(t, app, e, rawRequest("GET", "/", "", nil, false, tt.headers), tt.peer)
			if observed != tt.want {
				t.Fatalf("client=%s want=%s", observed, tt.want)
			}
		})
	}
}

func TestHostnameNormalizationAndStartupValidation(t *testing.T) {
	for raw, want := range map[string]string{"www.wow.test:443": "wow.test", "WWW.Example.TEST.": "example.test", "[2001:db8::1]:443": "2001:db8::1", "[::1]": "::1", "www.www.test": "www.test"} {
		got, err := normalizeHostname(raw)
		if err != nil || got != want {
			t.Errorf("%q = %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "example.test:bad", "example.test:65536", "bad/host", "[invalid]"} {
		if _, err := normalizeHostname(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, set := range []func(*config.Config){
		func(c *config.Config) { c.Firewall.WhitelistIPs = []string{"bad"} },
		func(c *config.Config) { c.Firewall.WhitelistNetworks = []string{"10.0.0.0/99"} },
		func(c *config.Config) { c.Firewall.TrustedProxies = []string{"bad"} },
	} {
		cfg := testConfig()
		set(&cfg)
		if _, err := New(cfg, nil, nil, nil); err == nil {
			t.Fatal("invalid startup network accepted")
		}
	}
}

func TestHostnameLengthBoundAndIPAuthorities(t *testing.T) {
	longName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	wwwBase := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57)
	for raw, want := range map[string]string{
		longName:                 longName,
		longName + ".":           longName,
		longName + ".:443":       longName,
		"www." + wwwBase + ":80": wwwBase,
		"192.0.2.1":              "192.0.2.1",
		"192.0.2.1:80":           "192.0.2.1",
		"2001:db8::1":            "2001:db8::1",
		"[2001:db8::1]":          "2001:db8::1",
		"[2001:db8::1]:443":      "2001:db8::1",
		"[::ffff:192.0.2.1]:80":  "192.0.2.1",
	} {
		got, err := normalizeHostname(raw)
		if err != nil || got != want {
			t.Errorf("%q normalized to %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		longName + "e", // 254 bytes with individually valid label lengths.
		"www." + longName,
		strings.Repeat("a", 4000),
		"fe80::1%lo0", "[fe80::1%lo0]", "[fe80::1%lo0]:80",
		"[fe80::1%" + strings.Repeat("x", 4000) + "]:80",
		strings.Repeat("\u023a", 126) + "a", // Lowercasing increases byte length.
	} {
		if got, err := normalizeHostname(raw); err == nil {
			t.Errorf("oversized/scoped host accepted: %q", got)
		}
	}
}

func TestPenaltyChallengeAndValidCookie(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.RequestThreshold = 1
	cfg.Firewall.SamplingWindow = time.Second
	e := testEngine(t, cfg, nil)
	app := testApp(e, func(c fiber.Ctx) error { return c.SendString("upstream") })
	raw := rawRequest("GET", "/", "", nil, false, "User-Agent: browser\r\n")
	first := serve(t, app, e, raw, "198.51.100.1")
	if string(first.Response.Body()) != "upstream" {
		t.Fatal("ordinary request challenged")
	}
	second := serve(t, app, e, raw, "198.51.100.1")
	var cookie fasthttp.Cookie
	cookie.SetKey(session.CookieName)
	if !second.Response.Header.Cookie(&cookie) || len(cookie.Value()) == 0 || !bytes.Contains(second.Response.Body(), []byte("refresh")) {
		t.Fatal("penalty did not issue challenge cookie")
	}
	third := serve(t, app, e, rawRequest("GET", "/", "", nil, false, "User-Agent: browser\r\nCookie: "+session.CookieName+"="+string(cookie.Value())+"\r\n"), "198.51.100.1")
	if string(third.Response.Body()) != "upstream" {
		t.Fatal("valid cookie was not accepted during penalty")
	}
}

func TestBudgetHeldUntilDownstreamCompletes(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.MaxBodyBytes = 64
	cfg.Firewall.MaxBufferedBytes = 65
	e := testEngine(t, cfg, nil)
	entered := make(chan struct{})
	finish := make(chan struct{})
	app := testApp(e, func(c fiber.Ctx) error { close(entered); <-finish; return c.SendStatus(200) })
	handler := app.Handler()
	raw := rawRequest("POST", "/", "application/json", []byte("x"), true, "")
	first, err := rawContext(raw, 64, "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); handler(first) }()
	<-entered
	second, err := rawContext(raw, 64, "198.51.100.2")
	if err != nil {
		t.Fatal(err)
	}
	handler(second)
	if second.Response.StatusCode() != 503 {
		t.Fatal("second buffered request exceeded budget")
	}
	if e.budget.used.Load() != 65 {
		t.Fatal("reservation released before downstream completed")
	}
	close(finish)
	<-done
	if e.budget.used.Load() != 0 {
		t.Fatal("reservation leaked")
	}
}

func TestSmallKnownBodiesShareBudgetWhileUnknownBodiesStayBounded(t *testing.T) {
	cfg := testConfig()
	cfg.Firewall.MaxBodyBytes = 64
	cfg.Firewall.MaxBufferedBytes = 65
	e := testEngine(t, cfg, nil)
	const requests = 16
	entered := make(chan struct{}, requests)
	finish := make(chan struct{})
	app := testApp(e, func(c fiber.Ctx) error {
		entered <- struct{}{}
		<-finish
		return c.SendStatus(200)
	})
	handler := app.Handler()
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		ctx, err := rawContext(rawRequest("POST", "/", "application/json", []byte("x"), false, ""), 64, "198.51.100.1")
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); handler(ctx) }()
	}
	for i := 0; i < requests; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(finish)
			wg.Wait()
			t.Fatal("small known-length bodies unnecessarily exhausted budget")
		}
	}
	if e.budget.used.Load() != requests*2 {
		close(finish)
		wg.Wait()
		t.Fatalf("known-length reservations = %d, want %d", e.budget.used.Load(), requests*2)
	}
	unknown, err := rawContext(rawRequest("POST", "/", "application/json", []byte("x"), true, ""), 64, "198.51.100.2")
	if err != nil {
		close(finish)
		wg.Wait()
		t.Fatal(err)
	}
	handler(unknown)
	if unknown.Response.StatusCode() != 503 {
		close(finish)
		wg.Wait()
		t.Fatal("unknown-length body did not reserve its full possible capacity")
	}
	close(finish)
	wg.Wait()
	if e.budget.used.Load() != 0 {
		t.Fatal("known-length reservations leaked")
	}
}

func TestEmptyBodiesRetainNoBudget(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "PATCH"} {
		for _, chunked := range []bool{false, true} {
			e := testEngine(t, testConfig(), nil)
			app := testApp(e, func(c fiber.Ctx) error {
				if used := e.budget.used.Load(); used != 0 {
					t.Errorf("%s chunked=%t empty body retained %d budget", method, chunked, used)
				}
				return c.SendStatus(200)
			})
			ctx := serve(t, app, e, rawRequest(method, "/", "", nil, chunked, ""), "198.51.100.1")
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("empty %s status %d", method, ctx.Response.StatusCode())
			}
		}
	}
}

func TestKnownEmptyRequestPassesInspectionWhenBudgetIsFull(t *testing.T) {
	e := testEngine(t, testConfig(), nil)
	e.budget.used.Store(e.budget.limit)
	app := fiber.New()
	for _, method := range []string{"GET", "POST"} {
		ctx, err := rawContext(rawRequest(method, "/", "", nil, false, ""), int(e.limits.MaxBodyBytes), "198.51.100.1")
		if err != nil {
			t.Fatal(err)
		}
		c := app.AcquireCtx(ctx)
		release, err := e.inspect(c)
		if release != nil {
			release()
		}
		if err != nil || ctx.Response.StatusCode() != 200 || e.budget.used.Load() != e.budget.limit {
			t.Fatalf("empty %s consumed full payload budget: status=%d used=%d err=%v", method, ctx.Response.StatusCode(), e.budget.used.Load(), err)
		}
		app.ReleaseCtx(c)
	}
}

func TestFixedWindowPenaltyExpiryAndConcurrentCounter(t *testing.T) {
	d := detector{hosts: cache.New[string, hostWindow](8), window: 10 * time.Second, penalty: time.Minute, threshold: 1}
	now := time.Unix(1700000000, 0)
	for i := 0; i < 19; i++ {
		if d.penalized("example.test", now) {
			t.Fatal("penalty began before v1 averaged threshold")
		}
	}
	if !d.penalized("example.test", now) {
		t.Fatal("threshold did not activate penalty")
	}
	if !d.penalized("example.test", now.Add(time.Minute-time.Nanosecond)) {
		t.Fatal("penalty ended early")
	}
	if d.penalized("example.test", now.Add(time.Minute)) {
		t.Fatal("penalty did not expire")
	}
	d.threshold = ^uint64(0)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				d.penalized("concurrent.test", now)
			}
		}()
	}
	wg.Wait()
	state, ok := d.hosts.Get("concurrent.test", now)
	if !ok || state.count != 16000 {
		t.Fatalf("lost concurrent increments: %+v", state)
	}
}

func TestDetectorClonesRetainedHost(t *testing.T) {
	d := detector{hosts: cache.New[string, hostWindow](8), window: 10 * time.Second, penalty: time.Minute, threshold: 200}
	bytes := []byte("example.test")
	view := unsafe.String(unsafe.SliceData(bytes), len(bytes))
	now := time.Now()
	d.penalized(view, now)
	for i := range bytes {
		bytes[i] = 'x'
	}
	if state, ok := d.hosts.Get("example.test", now); !ok || state.count != 1 {
		t.Fatal("detector retained mutable request host")
	}
	// Updates avoid a clone, so Cache.Set must preserve the existing owned key.
	second := []byte("example.test")
	d.penalized(unsafe.String(unsafe.SliceData(second), len(second)), now)
	for i := range second {
		second[i] = 'x'
	}
	if state, ok := d.hosts.Get("example.test", now); !ok || state.count != 2 {
		t.Fatal("detector update replaced its owned key with request storage")
	}
}

type countingReader struct {
	reader io.Reader
	reads  atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) { r.reads.Add(1); return r.reader.Read(p) }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

func TestEarlyHeaderRejectionAndReadFailure(t *testing.T) {
	e := testEngine(t, testConfig(), nil)
	app := fiber.New()
	for _, test := range []struct {
		ct     string
		reader io.Reader
		want   int
	}{
		{"multipart/form-data; boundary=\"", &countingReader{reader: strings.NewReader("payload")}, 400},
		{"application/json", failingReader{}, 400},
	} {
		ctx := new(fasthttp.RequestCtx)
		ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP("198.51.100.1")}, nil)
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetHost("example.test")
		ctx.Request.Header.SetContentType(test.ct)
		ctx.Request.SetBodyStream(test.reader, -1)
		c := app.AcquireCtx(ctx)
		release, err := e.inspect(c)
		if release != nil {
			release()
		}
		if err != nil || ctx.Response.StatusCode() != test.want {
			t.Fatalf("inspect: status=%d err=%v", ctx.Response.StatusCode(), err)
		}
		if reader, ok := test.reader.(*countingReader); ok && reader.reads.Load() != 0 {
			t.Fatal("read body before rejecting malformed content type")
		}
		app.ReleaseCtx(c)
	}
}

func TestSerializedExcerptBoundedAndEscaped(t *testing.T) {
	for _, body := range [][]byte{nil, []byte("a\r\n\x00\xff\"\\"), bytes.Repeat([]byte("a"), 28), bytes.Repeat([]byte("a"), 29), bytes.Repeat([]byte("é"), 1000), bytes.Repeat([]byte("a"), 2048)} {
		excerpt, truncated := serializedFormDataChunk(body)
		if len(excerpt) > 30 || strings.ContainsAny(excerpt, "\r\n") {
			t.Fatalf("unsafe excerpt %q", excerpt)
		}
		decoded, err := strconv.Unquote(excerpt)
		if err != nil || !bytes.HasPrefix(body, []byte(decoded)) || truncated != (len(decoded) < len(body)) {
			t.Fatal("excerpt changed the payload prefix or reported incorrect truncation")
		}
	}
}

func TestTextLoggerSerializesExcerptOnceWithinLimit(t *testing.T) {
	for _, body := range [][]byte{
		bytes.Repeat([]byte("\\\"\r\n\x00\xff"), 300),
		bytes.Repeat([]byte("é"), 1000),
		bytes.Repeat([]byte("a"), 2048),
		bytes.Repeat([]byte("a"), 28),
		bytes.Repeat([]byte("a"), 29),
		[]byte("short \"text\"\r\n"),
	} {
		var output bytes.Buffer
		e := testEngine(t, testConfig(), nil)
		e.logger = slog.New(slog.NewTextHandler(&output, nil))
		app := fiber.New()
		ctx := new(fasthttp.RequestCtx)
		ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP("198.51.100.9")}, nil)
		c := app.AcquireCtx(ctx)
		c.Locals(clientIPKey{}, "198.51.100.9")
		if err := e.reject(c, 400, cve2026109618.ErrMalformed, body); err != nil {
			t.Fatal(err)
		}
		app.ReleaseCtx(c)
		line := output.String()
		if strings.Count(line, "\n") != 1 || !strings.Contains(line, "client_ip=198.51.100.9") {
			t.Fatalf("unsafe or unidentified log line: %q", line)
		}
		start := strings.Index(line, " form_data=")
		end := strings.Index(line, " form_data_truncated=")
		if start < 0 || end <= start {
			t.Fatalf("missing excerpt fields: %q", line)
		}
		field := line[start+len(" form_data=") : end]
		if len(field) > 30 {
			t.Fatalf("serialized field grew to %d bytes", len(field))
		}
		decoded := field
		if strings.HasPrefix(field, "\"") {
			var err error
			decoded, err = strconv.Unquote(field)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.HasPrefix(body, []byte(decoded)) {
			t.Fatalf("excerpt changed bytes: %q", decoded)
		}
		if truncated := len(decoded) < len(body); !strings.Contains(line, fmt.Sprintf("form_data_truncated=%t", truncated)) {
			t.Fatalf("wrong truncation flag: %q", line)
		}
	}
}
