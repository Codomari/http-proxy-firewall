package admin

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/monitoring"
)

func TestLogTailInitialAppendAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var data strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&data, "line %d\n", i)
	}
	write(data.String())
	tail := logTail{path: path}
	read := func(cursor string) logBatch {
		t.Helper()
		b, err := tail.read(cursor)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := read("")
	if !first.Reset || len(first.Lines) != 100 || first.Lines[0] != "line 50" || first.Lines[99] != "line 149" {
		t.Fatalf("incorrect tail: %+v", first)
	}
	idle := read(first.Cursor)
	if idle.Reset || len(idle.Lines) != 0 {
		t.Fatal("idle poll repeated logs")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("<script>alert(1)</script>\npartial"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	next := read(idle.Cursor)
	if next.Reset || !reflect.DeepEqual(next.Lines, []string{"<script>alert(1)</script>"}) {
		t.Fatalf("append lost or repeated lines: %+v", next)
	}
	if b := read(next.Cursor); len(b.Lines) != 0 {
		t.Fatal("unfinished line published")
	}
	file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(" completed\n")
	file.Close()
	completed := read(next.Cursor)
	if !reflect.DeepEqual(completed.Lines, []string{"partial completed"}) {
		t.Fatal("partial line lost")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write("rotated\n")
	rotated := read(completed.Cursor)
	if !rotated.Reset || !reflect.DeepEqual(rotated.Lines, []string{"rotated"}) {
		t.Fatal("rename rotation not detected")
	}
	// Regrow beyond the old offset to exercise the anchor, not just size.
	write("copytruncate with a longer replacement\n")
	truncated := read(rotated.Cursor)
	if !truncated.Reset || !reflect.DeepEqual(truncated.Lines, []string{"copytruncate with a longer replacement"}) {
		t.Fatal("copytruncate regrowth not detected")
	}
}

func TestLogTailBoundsAndInvalidCursors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxLogRead+100)+"\nend\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tail := logTail{path: path}
	for _, cursor := range []string{"", "bad cursor", base64.RawURLEncoding.EncodeToString([]byte(`{"g":1,"o":-1}`)), strings.Repeat("x", 1000)} {
		batch, err := tail.read(cursor)
		if err != nil || !batch.Reset || !batch.Limited || len(batch.Lines) != 1 || batch.Lines[0] != "end" {
			t.Fatalf("unbounded or invalid tail: %+v %v", batch, err)
		}
	}
	if err := os.WriteFile(path, []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, _ := tail.read("")
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	file.WriteString(strings.Repeat("a", maxLogRead+200) + "\nend\n")
	file.Close()
	next, err := tail.read(first.Cursor)
	if err != nil || !next.More || !next.Limited || len(next.Lines) != 1 || len(next.Lines[0]) > 4200 {
		t.Fatalf("oversized line pinned cursor: %+v %v", next, err)
	}
	last, err := tail.read(next.Cursor)
	if err != nil || last.More || last.Lines[len(last.Lines)-1] != "end" {
		t.Fatal("large append did not drain")
	}
}

func TestLogEndpointAuthenticationAndFixedPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = true
	cfg.Admin.URI = "ops"
	cfg.Admin.Accounts = []config.AdminAccount{{User: "test-admin", Password: "test-password:with-colon"}}
	h, err := New(cfg, monitoring.New(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.logs.path = filepath.Join(t.TempDir(), "service.log")
	if err := os.WriteFile(h.logs.path, []byte("safe log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	h.Mount(app)
	for _, auth := range []string{"", basic("test-admin", "wrong")} {
		if resp := request(t, app, http.MethodGet, "/ops/api/logs", auth); resp.StatusCode != 401 {
			t.Fatal("log endpoint bypassed authentication")
		}
	}
	resp := request(t, app, http.MethodGet, "/ops/api/logs?path=/etc/passwd", validBasic())
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "safe log") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("fixed log endpoint failed: %s", body)
	}
	if resp := request(t, app, http.MethodPost, "/ops/api/logs", validBasic()); resp.StatusCode != 405 {
		t.Fatal("log endpoint accepted writes")
	}
	h.enabled = false
	if resp := request(t, app, http.MethodGet, "/ops/api/logs", validBasic()); resp.StatusCode != 404 {
		t.Fatal("disabled admin exposed logs")
	}
	h.enabled = true
	h.logs.path += ".missing"
	if resp := request(t, app, http.MethodGet, "/ops/api/logs", validBasic()); resp.StatusCode != 503 {
		t.Fatal("missing log did not return unavailable")
	}
}
