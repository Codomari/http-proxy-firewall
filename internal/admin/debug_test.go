package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"
)

func TestDebugHostnamePatternsAndSafeFilenames(t *testing.T) {
	for _, raw := range []string{"example.com", "WWW.Example.COM.", "*.example.com", "localhost", strings.Repeat("a", 63) + ".example.com"} {
		name, err := debugHostname(raw)
		if err != nil || !regexp.MustCompile(`^[a-z0-9-]+\.log$`).MatchString(debugFilename(name, "")) {
			t.Fatalf("valid hostname %q failed: %q %v", raw, name, err)
		}
	}
	for _, raw := range []string{"", "*", "*example.com", "foo.*.com", "https://example.com", "example.com:80", "../../etc/passwd", "a/b", "a\\b", "a\nb", "a_b", "a..b", "-a.com", "a-.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := debugHostname(raw); err == nil {
			t.Fatalf("unsafe hostname accepted: %q", raw)
		}
	}
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true}, {"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true}, {"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false}, {"*.example.com", "notexample.com", false},
		{"*.example.com", "example.com.evil", false},
	} {
		if got := debugMatches(tc.pattern, tc.host); got != tc.want {
			t.Fatalf("%q matches %q: %v", tc.pattern, tc.host, got)
		}
	}
	if debugFilename("a.b", "") == debugFilename("a-b", "") || debugFilename("*.example.com", "") == debugFilename("wildcard.example.com", "") {
		t.Fatal("distinct host patterns share a log file")
	}
	long := strings.Repeat("a.", 120) + "example.com"
	if len(debugFilename(long, "")) > 255 {
		t.Fatal("log basename exceeds filesystem limit")
	}
	if got := debugEscape("/a\n[forged]\r\x1b"); strings.ContainsAny(got, "\n\r\x1b") || !strings.Contains(got, `\n`) {
		t.Fatal("untrusted text can forge log lines or terminal escapes")
	}
}

func TestDebugSourceIPFilter(t *testing.T) {
	for _, raw := range []string{"bad", "203.0.113.1/24", "203.0.113.1:80", "fe80::1%eth0", "2001:db8::1\nforged"} {
		if _, err := debugSourceIP(raw); err == nil {
			t.Fatalf("invalid source IP accepted: %q", raw)
		}
	}
	for raw, want := range map[string]string{"": "", " 203.0.113.8 ": "203.0.113.8", "2001:0db8::1": "2001:db8::1", "::ffff:203.0.113.8": "203.0.113.8"} {
		if got, err := debugSourceIP(raw); err != nil || got != want {
			t.Fatalf("source normalization: %q => %q, %v", raw, got, err)
		}
	}
	for _, source := range []string{"203.0.113.8", "2001:db8::1"} {
		h := &Handler{}
		h.debug.dir = t.TempDir()
		status, err := h.debug.set("*.example.com", source)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[a-z0-9-]+\.log$`).MatchString(filepath.Base(status.File)) || status.ClientIP != source {
			t.Fatal("source filter missing from status or unsafe filename")
		}
		resolved := source
		app := fiber.New()
		app.Use(h.DebugMiddleware(func(fiber.Ctx) string { return resolved }))
		app.Use(func(c fiber.Ctx) error { return c.SendStatus(200) })
		for _, tc := range []struct{ host, ip, path string }{
			{"a.example.com", source, "/match"}, {"a.example.com", "198.51.100.1", "/wrong-ip"},
			{"example.com", source, "/wrong-host"},
		} {
			resolved = tc.ip
			resp, err := app.Test(httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		data, err := os.ReadFile(status.File)
		if err != nil || strings.Count(string(data), "\n") != 1 || !strings.Contains(string(data), "GET /match") {
			t.Fatalf("source filter failed: %s %v", data, err)
		}
		unfiltered, err := h.debug.set("*.example.com", "")
		if err != nil || unfiltered.File == status.File {
			t.Fatal("filtered and unfiltered captures share history")
		}
		if _, err := h.debug.set("*.example.com", "bad-ip"); err == nil || h.debug.snapshot(false).File != unfiltered.File {
			t.Fatal("invalid source filter changed active capture")
		}
	}
}

func TestDebugControlsCaptureAndViewer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled, cfg.Admin.URI = true, "ops"
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	h, err := New(cfg, monitoring.New(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.debug.dir = t.TempDir()
	app := fiber.New(fiber.Config{ReadBufferSize: 16 << 10})
	h.Mount(app)
	app.Use(h.DebugMiddleware(func(fiber.Ctx) string { return "203.0.113.8" }))
	app.Use(func(c fiber.Ctx) error { return c.SendStatus(403) })
	control := func(method, hostname string, auth, csrf bool) *http.Response {
		t.Helper()
		req := httptest.NewRequest(method, "http://admin.example/ops/api/debug?hostname="+url.QueryEscape(hostname), nil)
		if auth {
			req.Header.Set("Authorization", validBasic())
		}
		if csrf {
			req.Header.Set("X-PF-Admin", "1")
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	for _, method := range []string{"GET", "POST", "DELETE"} {
		if control(method, "example.com", false, true).StatusCode != 401 {
			t.Fatal("debug controls bypassed authentication")
		}
	}
	if resp := request(t, app, "GET", "/ops/api/debug/logs", ""); resp.StatusCode != 401 {
		t.Fatal("debug viewer bypassed authentication")
	}
	for _, method := range []string{"POST", "DELETE"} {
		if control(method, "example.com", true, false).StatusCode != 403 {
			t.Fatal("debug mutation lacks CSRF protection")
		}
	}
	if control("GET", "example.com", true, true).StatusCode != 200 || h.debug.active.Load() {
		t.Fatal("GET enabled debug")
	}
	if control("POST", "../../etc/passwd", true, true).StatusCode != 400 {
		t.Fatal("debug accepted a filesystem path")
	}
	resp := control("POST", "Example.COM.", true, true)
	var status debugStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil || resp.StatusCode != 200 || !status.Enabled || status.Hostname != "example.com" {
		t.Fatalf("enable debug: %+v %v", status, err)
	}
	for _, host := range []string{"EXAMPLE.com:80", "other.example.com"} {
		req := httptest.NewRequest("GET", "http://"+host+"/MiXeD%2fPath//?q=%2f&x=+", nil)
		req.Header.Add("X-Debug-Test", "<script>alert(1)</script>")
		req.Header.Add("X-Debug-Test", "second-value")
		req.Header.Set("Cookie", "token="+strings.Repeat("a", 6000))
		req.Header.Set("Authorization", "Bearer backend-token")
		resp, err := app.Test(req)
		if err != nil || resp.StatusCode != 403 {
			t.Fatalf("traffic failed: %v", err)
		}
		resp.Body.Close()
	}
	read := func() logBatch {
		t.Helper()
		resp := request(t, app, "GET", "/ops/api/debug/logs?path=/etc/passwd", validBasic())
		var batch logBatch
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil || resp.StatusCode != 200 {
			t.Fatalf("debug viewer: status=%d %v", resp.StatusCode, err)
		}
		return batch
	}
	batch := read()
	if len(batch.Lines) != 1 || batch.Limited {
		t.Fatalf("exact capture did not retain full headers: lines=%d limited=%v", len(batch.Lines), batch.Limited)
	}
	line := batch.Lines[0]
	end := strings.Index(line, "]")
	if end < 0 {
		t.Fatal("missing timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, line[1:end]); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FROM: 203.0.113.8, TO: example.com, GET /MiXeD%2fPath//?q=%2f&x=+ [", "<script>alert(1)</script>", "second-value", "Bearer backend-token", strings.Repeat("a", 6000)} {
		if !strings.Contains(line, want) {
			t.Fatalf("debug line omitted %q", want[:min(80, len(want))])
		}
	}
	if info, err := os.Stat(status.File); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("debug log is not private")
	}
	if control("POST", "bad/path", true, true).StatusCode != 400 || h.debug.snapshot(false).Hostname != "example.com" {
		t.Fatal("invalid replacement altered active capture")
	}
	if control("DELETE", "", true, true).StatusCode != 200 || h.debug.active.Load() {
		t.Fatal("disable failed")
	}
	before, _ := os.ReadFile(status.File)
	traffic, _ := app.Test(httptest.NewRequest("GET", "http://example.com/after-disable", nil))
	traffic.Body.Close()
	after, _ := os.ReadFile(status.File)
	if string(before) != string(after) || len(read().Lines) != 1 {
		t.Fatal("disable wrote new requests or lost existing logs")
	}
	h.enabled = false
	for _, path := range []string{"/ops/api/debug", "/ops/api/debug/logs"} {
		if request(t, app, "GET", path, validBasic()).StatusCode != 404 {
			t.Fatal("disabled admin exposed debug")
		}
	}
}

func TestDebugConcurrentAppendsDisableAndFileFailure(t *testing.T) {
	h := &Handler{}
	h.debug.dir = t.TempDir()
	status, err := h.debug.set("*.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Use(h.DebugMiddleware(func(fiber.Ctx) string { return "203.0.113.1" }))
	app.Use(func(c fiber.Ctx) error { return c.SendStatus(200) })
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			resp, err := app.Test(httptest.NewRequest("GET", "http://a.example.com/test", nil))
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		})
	}
	wg.Wait()
	h.debug.snapshot(true)
	data, err := os.ReadFile(status.File)
	if err != nil || strings.Count(string(data), "\n") != 20 {
		t.Fatal("concurrent capture lost lines")
	}
	// Replacing a file with a symlink cannot redirect extended headers elsewhere.
	other := filepath.Join(h.debug.dir, "private")
	if err := os.WriteFile(other, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(status.File, status.File+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, status.File); err != nil {
		t.Fatal(err)
	}
	if _, err := h.debug.set("*.example.com", ""); err == nil {
		t.Fatal("debug accepted a symlink destination")
	}
}

func TestDebugStructuredEntriesPreserveRequestData(t *testing.T) {
	stamp := "2026-11-03T12:34:56.123456Z"
	url := `/MiXeD%2fPath//?q=%2f&plus=+&quote="`
	header := "comma, bracket ] [ quote \" newline\n<script>alert(1)</script>"
	line := "[" + stamp + "] FROM: 2001:db8::8, TO: api.example.com, CUSTOM " + debugEscape(url) + " [Host: \"api.example.com\", X-Test: " + strconv.QuoteToASCII(header) + ", X-Test: \"second\"]"
	want := debugEntry{Timestamp: stamp, ClientIP: "2001:db8::8", Hostname: "api.example.com", Method: "CUSTOM", URL: url, Headers: []debugHeader{{Name: "Host", Value: "api.example.com"}, {Name: "X-Test", Value: header}, {Name: "X-Test", Value: "second"}}}
	if got := parseDebugEntry(line); !reflect.DeepEqual(got, want) {
		t.Fatalf("structured entry changed request data: got=%+v want=%+v", got, want)
	}
	for _, line := range []string{"", "legacy or truncated log entry", "[invalid-date] FROM: x", strings.TrimSuffix(line, "]"), strings.Replace(line, `"second"`, `unquoted`, 1)} {
		got := parseDebugEntry(line)
		if got.Raw == nil || *got.Raw != line {
			t.Fatalf("unparseable entry was lost: %q", line)
		}
	}
}

func TestDebugStructuredPollingAppendIdleAndRuleChange(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled, cfg.Admin.URI = true, "ops"
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	h, err := New(cfg, monitoring.New(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.debug.dir = t.TempDir()
	app := fiber.New()
	h.Mount(app)
	read := func(host, ip, cursor string) debugBatch {
		t.Helper()
		query := url.Values{"hostname": {host}, "client_ip": {ip}, "cursor": {cursor}}
		resp := request(t, app, "GET", "/ops/api/debug/logs?"+query.Encode(), validBasic())
		var batch debugBatch
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil || resp.StatusCode != 200 {
			t.Fatalf("debug poll failed: status=%d err=%v", resp.StatusCode, err)
		}
		return batch
	}
	if batch := read("", "", ""); batch.Entries == nil || len(batch.Entries) != 0 {
		t.Fatal("disabled capture did not return an empty table")
	}
	status, err := h.debug.set("example.com", "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	appendLine := func(path string) {
		t.Helper()
		line := "[2026-11-03T12:34:56Z] FROM: 203.0.113.8, TO: example.com, GET " + path + " [Host: \"example.com\"]\n"
		file, err := os.OpenFile(status.File, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	appendLine("/first")
	first := read(status.Hostname, status.ClientIP, "")
	if len(first.Entries) != 1 || first.Entries[0].URL != "/first" || !first.Reset {
		t.Fatalf("initial table: %+v", first)
	}
	idle := read(status.Hostname, status.ClientIP, first.Cursor)
	if len(idle.Entries) != 0 || idle.Reset {
		t.Fatal("idle polling duplicated table rows")
	}
	appendLine("/second")
	next := read(status.Hostname, status.ClientIP, idle.Cursor)
	if len(next.Entries) != 1 || next.Entries[0].URL != "/second" || next.Reset {
		t.Fatal("next poll failed to read only appended requests")
	}
	if _, err := h.debug.set("other.example", ""); err != nil {
		t.Fatal(err)
	}
	changed := read(status.Hostname, status.ClientIP, next.Cursor)
	if changed.Status.Hostname != "other.example" || len(changed.Entries) != 0 || !changed.Reset {
		t.Fatal("new capture leaked rows from the previous rule")
	}
}
