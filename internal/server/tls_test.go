package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func certificateFiles(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "test.crt"), filepath.Join(dir, "test.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("load test root")
	}
	return certFile, keyFile, roots
}

func TestStaticTLSKeepsConnectionsAliveAndForwardsHTTPSOrigin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" || r.Host != "tenant.example" {
			t.Errorf("forwarded origin = %q %q", r.Header.Get("X-Forwarded-Proto"), r.Host)
		}
		_, _ = io.WriteString(w, "secure")
	}))
	defer upstream.Close()
	cfg := serverConfig(upstream.URL)
	certFile, keyFile, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, certFile, keyFile
	s := newTestServer(t, cfg)
	if s.manager != nil {
		t.Fatal("static TLS unexpectedly configured ACME")
	}
	setup, err := s.tlsConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if setup.MinVersion != tls.VersionTLS12 || setup.GetCertificate != nil || len(setup.Certificates) != 1 {
		t.Fatalf("unexpected static TLS setup: %+v", setup)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for i := range 2 {
		request, err := http.NewRequest(http.MethodGet, "https://"+s.TLSAddress().String()+"/secure", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "tenant.example"
		reused := false
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "secure" {
			t.Fatalf("response = %d %q %v", response.StatusCode, body, err)
		}
		if response.Close || response.Header.Get("Connection") == "close" || response.Header.Get("Strict-Transport-Security") != "max-age=0" {
			t.Errorf("TLS response headers = %v", response.Header)
		}
		if i == 1 && !reused {
			t.Error("TLS client connection was not reused")
		}
	}
}

func TestInvalidStaticTLSFailsBeforeBinding(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, "/missing/test.crt", "/missing/test.key"
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected invalid certificate error")
	}
	if s.HTTPAddress() != nil {
		t.Error("HTTP bound before invalid TLS was detected")
	}
}

func TestMonitoringSharesHTTPAndHTTPSWhileKeepingWWWHostsDistinct(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	cfg := adminConfig(upstream.URL)
	certFile, keyFile, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, certFile, keyFile
	s := startAdminTestServer(t, cfg)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, request := range []struct{ target, host string }{
		{"http://" + s.HTTPAddress().String(), "Example.COM:8080"},
		{"https://" + s.TLSAddress().String(), "example.com"},
		{"https://" + s.TLSAddress().String(), "WWW.example.com."},
	} {
		req, _ := http.NewRequest(http.MethodGet, request.target+"/ordinary", nil)
		req.Host = request.host
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("request status = %d", response.StatusCode)
		}
	}
	waitForNoInFlight(t, s)
	totals, hosts := readOverview(t, s)
	counts := make(map[string]uint64, len(hosts))
	for _, host := range hosts {
		counts[host.Hostname] = host.Requests
	}
	if totals.Requests != 3 || len(counts) != 2 || counts["example.com"] != 2 || counts["www.example.com"] != 1 {
		t.Fatalf("shared HTTP/HTTPS counts = %+v, hosts %+v", totals, hosts)
	}
}
