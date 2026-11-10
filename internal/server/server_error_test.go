package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/net/http2"
)

func TestUpstreamServerErrorsUseLocalizedPages(t *testing.T) {
	const originBody = "private origin error"
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		status, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(originBody)))
		w.Header().Set("Content-Disposition", "attachment; filename=error.json")
		w.Header().Set("ETag", `"origin"`)
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, originBody)
	}))
	defer backend.Close()
	cfg := serverConfig(backend.URL)
	cfg.HTTP.HTTP2Enable = true
	cfg.Proxy.MaxConnections = 1
	cfg.Proxy.Routes = map[string]string{"routed.example": backend.URL}
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	s := newTestServer(t, cfg)
	s.statusCountry = func(fiber.Ctx) string { return "Portugal" }
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h1 := &http.Transport{}
	h2 := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer h1.CloseIdleConnections()
	defer h2.CloseIdleConnections()
	for _, protocol := range []struct {
		name, address string
		transport     http.RoundTripper
		major         int
	}{
		{"http1", "http://" + s.HTTPAddress().String(), h1, 1},
		{"http2", "https://" + s.TLSAddress().String(), h2, 2},
	} {
		client := &http.Client{Transport: protocol.transport, Timeout: 2 * time.Second}
		for _, status := range []int{500, 502, 503} {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				t.Run(protocol.name+"/"+strconv.Itoa(status)+"/"+method, func(t *testing.T) {
					request, _ := http.NewRequest(method, protocol.address+"/"+strconv.Itoa(status)+"?token=private-query", nil)
					if method == "POST" {
						request.Host = "routed.example"
					}
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || response.StatusCode != status || response.ProtoMajor != protocol.major {
						t.Fatalf("status=%d protocol=%s read=%v", response.StatusCode, response.Proto, err)
					}
					for name, want := range map[string]string{
						"Content-Type": "text/html; charset=utf-8", "Content-Language": "pt", "Cache-Control": "no-store", "Retry-After": "120",
						"Content-Encoding": "", "Content-Disposition": "", "ETag": "", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
					} {
						if got := response.Header.Get(name); got != want {
							t.Errorf("%s=%q want=%q", name, got, want)
						}
					}
					if !strings.Contains(response.Header.Get("Content-Security-Policy"), assetHash(statusLanguageJS)) {
						t.Fatal("language switcher blocked by CSP")
					}
					if method == "HEAD" {
						if len(body) != 0 {
							t.Fatal("HEAD returned a body")
						}
						return
					}
					for _, want := range []string{`lang="pt"`, "<small>" + strconv.Itoa(status) + "</small>", `id="status-language"`} {
						if !strings.Contains(string(body), want) {
							t.Errorf("missing %q", want)
						}
					}
					if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
						t.Fatalf("Content-Length=%d body=%d", response.ContentLength, len(body))
					}
					if strings.Contains(string(body), originBody) || strings.Contains(string(body), "private-query") {
						t.Fatal("replacement page exposed origin or request details")
					}
				})
			}
		}
	}
	if calls.Load() != 18 {
		t.Fatalf("upstream calls=%d want=18; status responses must not be retried", calls.Load())
	}
}

func TestOtherUpstreamStatusesRetainTheirResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("ETag", `"origin"`)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "original response")
	}))
	defer backend.Close()
	s := newTestServer(t, serverConfig(backend.URL))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport}
	for _, status := range []int{200, 400, 409, 413, 504, 508} {
		response, err := client.Get("http://" + s.HTTPAddress().String() + "/" + strconv.Itoa(status))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != status || string(body) != "original response" || response.Header.Get("ETag") != `"origin"` || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("origin response changed for status %d", status)
		}
	}
}

func TestServerErrorPagesDiscardStalledBodiesAndReleaseConnections(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		status, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		w.WriteHeader(status)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	cfg := adminConfig(backend.URL)
	cfg.Proxy.MaxConnections = 1
	cfg.Proxy.ReadTimeout = 5 * time.Second
	s := startAdminTestServer(t, cfg)
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport}
	base := "http://" + s.HTTPAddress().String()
	var bytesOut uint64
	for _, upgrade := range []bool{false, true} {
		for _, status := range []int{500, 502, 503} {
			request, _ := http.NewRequest("GET", base+"/"+strconv.Itoa(status), nil)
			if upgrade {
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("waited for a stalled error body", err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			bytesOut += uint64(len(body))
			if err != nil || response.StatusCode != status || !strings.Contains(string(body), "<small>"+strconv.Itoa(status)+"</small>") {
				t.Fatalf("upgrade=%v status=%d read=%v", upgrade, response.StatusCode, err)
			}
			response, err = client.Get(base + "/ok")
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(response.Body)
			_ = response.Body.Close()
			bytesOut += uint64(len(body))
			if err != nil || response.StatusCode != 200 || string(body) != "ok" {
				t.Fatal("discarded response retained the only upstream slot")
			}
		}
	}
	waitForNoInFlight(t, s)
	totals, hosts := readOverview(t, s)
	if totals.Requests != 12 || totals.Errors5xx != 6 || len(hosts) != 1 || hosts[0].BytesOut != bytesOut {
		t.Fatalf("replacement response accounting: totals=%+v hosts=%+v want bytes=%d", totals, hosts, bytesOut)
	}
}

func TestLocalServerFailuresUseStatusPages(t *testing.T) {
	s := newTestServer(t, serverConfig("http://127.0.0.1:1"))
	s.statusCountry = func(fiber.Ctx) string { return "Turkey" }
	for _, tc := range []struct {
		name   string
		status int
		run    fiber.Handler
	}{
		{"connection failure", 502, s.upstream.Handle},
		{"admission", 503, func(c fiber.Ctx) error {
			s.admission.limit = 0
			return s.admissionHandler()(c)
		}},
		{"internal error", 500, func(fiber.Ctx) error { return errors.New("private failure detail") }},
		{"typed error", 503, func(fiber.Ctx) error { return fiber.ErrServiceUnavailable }},
		{"panic", 500, func(c fiber.Ctx) error {
			s.admission.limit = 1
			return s.admissionHandler()(c)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newFiberApp(s.cfg)
			app.Use(s.serverErrorPage)
			app.Use(tc.run)
			app.Use(func(fiber.Ctx) error { panic("private panic detail") })
			response, err := app.Test(httptest.NewRequest("GET", "http://example.test/", nil))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != tc.status || response.Header.Get("Content-Language") != "tr" || !strings.Contains(string(body), "<small>"+strconv.Itoa(tc.status)+"</small>") || strings.Contains(string(body), "private") {
				t.Fatalf("status=%d language=%s read=%v", response.StatusCode, response.Header.Get("Content-Language"), err)
			}
			if tc.name == "admission" && response.Header.Get("Retry-After") != "1" {
				t.Fatal("lost capacity retry guidance")
			}
		})
	}
}
