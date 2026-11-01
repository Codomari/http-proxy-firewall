package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectionWarningLogsPeerWithoutRawErrorText(t *testing.T) {
	for _, peer := range []string{"198.51.100.9", "2001:db8::9", "::ffff:198.51.100.9"} {
		t.Run(peer, func(t *testing.T) {
			var output bytes.Buffer
			logger := &safeLogger{logger: slog.New(slog.NewTextHandler(&output, nil))}
			args := []any{
				&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
				&net.TCPAddr{IP: net.ParseIP(peer), Port: 54321},
				errors.New("private request header must not be logged"),
			}
			for range 2 {
				logger.Printf("error when serving connection %q<->%q: %v", args...)
			}
			line := output.String()
			if strings.Count(line, "\n") != 1 || !strings.Contains(line, `msg="HTTP connection failed"`) || !strings.Contains(line, "client_ip="+net.ParseIP(peer).String()+"\n") {
				t.Fatalf("missing peer IP or lost error sampling: %q", line)
			}
			if strings.Contains(line, "54321") || strings.Contains(line, "192.0.2.1") || strings.Contains(line, "private request") {
				t.Fatalf("warning exposed local address, port or raw error text: %q", line)
			}
		})
	}
}

func TestConnectionWarningWithoutPeer(t *testing.T) {
	var output bytes.Buffer
	logger := &safeLogger{logger: slog.New(slog.NewTextHandler(&output, nil))}
	logger.Printf("Permanent error when accepting new connections: %v", errors.New("private error"))
	if !strings.Contains(output.String(), "client_ip=unknown") || strings.Contains(output.String(), "private error") {
		t.Fatalf("listener warning invented a client IP or leaked its error: %q", output.String())
	}
}

type connectionLogLines chan string

func (lines connectionLogLines) Write(data []byte) (int, error) {
	lines <- string(data)
	return len(data), nil
}

func TestNativeTLSFailureLogsConnectionIP(t *testing.T) {
	cfg := serverConfig("http://127.0.0.1:1")
	certFile, keyFile, _ := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, certFile, keyFile
	s := newTestServer(t, cfg)
	lines := make(connectionLogLines, 16)
	s.app.Server().Logger = &safeLogger{logger: slog.New(slog.NewTextHandler(lines, nil))}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", s.TLSAddress().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\nCF-Connecting-IP: 203.0.113.99\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, conn)
	select {
	case line := <-lines:
		if !strings.Contains(line, `msg="HTTP connection failed"`) || !strings.Contains(line, "client_ip=127.0.0.1") || strings.Contains(line, "203.0.113.99") {
			t.Fatalf("native connection warning lost peer or trusted unparsed headers: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native TLS failure did not emit a warning")
	}
}
