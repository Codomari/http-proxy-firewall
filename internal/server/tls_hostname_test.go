package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/net/http2"
)

func TestTLSWithoutSNIReturnsTranslatedConflictWithoutIssuingCertificate(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer backend.Close()
	for _, static := range []bool{false, true} {
		cfg := serverConfig(backend.URL)
		cfg.TLS.Enabled = true
		if static {
			cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, _ = certificateFiles(t)
		}
		s := newTestServer(t, cfg)
		s.statusCountry = func(fiber.Ctx) string { return "Azerbaijan" }
		s.certGuard.client.Transport = certificateRoundTrip(func(*http.Request) (*http.Response, error) {
			t.Error("missing SNI triggered a certificate probe")
			return nil, context.Canceled
		})
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		address := "https://" + s.TLSAddress().String()
		tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // Test the HTTP status after the fallback handshake.
		http1 := &http.Transport{TLSClientConfig: tlsConfig}
		// Override h2's automatic ServerName so it sends no SNI even for request.Host.
		h2 := &http2.Transport{TLSClientConfig: tlsConfig, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}}).DialContext(ctx, network, addr)
		}}
		for _, transport := range []http.RoundTripper{http1, h2} {
			client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
			for _, method := range []string{"GET", "HEAD", "POST"} {
				r, _ := http.NewRequest(method, address+"/secure", nil)
				r.Host = "site.example" // An HTTP Host header cannot replace missing TLS SNI.
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if response.StatusCode != 409 || response.Header.Get("Content-Language") != "az" || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("conflict headers: %s %v", response.Status, response.Header)
				}
				if method == "HEAD" {
					if len(body) != 0 {
						t.Fatal("HEAD returned a body")
					}
				} else if !strings.Contains(string(body), statusPageForCountry("Azerbaijan").tlsHostnameRequired) {
					t.Fatal("translated hostname-required page missing")
				}
			}
		}
		http1.CloseIdleConnections()
		h2.CloseIdleConnections()
	}
	if calls.Load() != 0 {
		t.Fatal("missing-SNI request reached upstream")
	}
}
