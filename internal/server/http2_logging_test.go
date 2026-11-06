package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHTTP2LogWriterUsesStructuredFieldsAndSampling(t *testing.T) {
	s := newTestServer(t, serverConfig("http://127.0.0.1:1"))
	var output bytes.Buffer
	s.app.Server().Logger = &safeLogger{logger: slog.New(slog.NewTextHandler(&output, nil))}
	message := "http2: server: error reading preface from client [2001:db8::9]:58470: connection reset by peer\n"
	for range 2 {
		if _, err := s.h2Base.ErrorLog.Writer().Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
	}
	line := output.String()
	for _, want := range []string{"time=", "level=WARN", `msg="HTTP connection failed"`, "client_ip=2001:db8::9", `error="http2: server: error reading preface`} {
		if !strings.Contains(line, want) {
			t.Fatalf("structured HTTP/2 field missing: %q", line)
		}
	}
	if strings.Count(line, "\n") != 1 || strings.Contains(line, "2026/") {
		t.Fatal("unstructured or unsampled HTTP/2 logs")
	}
}

func TestHTTP2PrefaceFailureLogsPeerAndSNI(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	s := newTestServer(t, cfg)
	lines := make(connectionLogLines, 8)
	s.app.Server().Logger = &safeLogger{logger: slog.New(slog.NewTextHandler(lines, nil)), hostname: s.connectionHostname}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.TLSAddress().String(), &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	// Negotiate h2, then send a complete invalid preface to force the native log.
	_, _ = io.WriteString(conn, "INVALID HTTP2 PREFACE!!!!")
	_ = conn.Close()
	select {
	case line := <-lines:
		for _, want := range []string{"time=", "level=WARN", `msg="HTTP connection failed"`, "client_ip=127.0.0.1", "hostname=localhost", "preface"} {
			if !strings.Contains(line, want) {
				t.Fatalf("HTTP/2 native warning missing %s: %s", want, line)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/2 preface failure was not logged")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
