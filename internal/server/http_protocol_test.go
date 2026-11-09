package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestTLSProtocolControlsPreserveCertificateRenewal(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := serverConfig("http://127.0.0.1:1")
		cfg.TLS.Enabled, cfg.HTTP.HTTP2Enable = true, enabled
		s := newTestServer(t, cfg)
		setup, err := s.tlsConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(setup.NextProtos, "http/1.1") || !slices.Contains(setup.NextProtos, acme.ALPNProto) || slices.Contains(setup.NextProtos, "h2") != enabled || slices.Contains(setup.NextProtos, "h3") {
			t.Fatalf("incorrect HTTP/ACME protocols: %v", setup.NextProtos)
		}
	}
}

func TestHTTP1DefaultAndHTTP2OptInKeepHTTPAndHTTPSAvailable(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	for _, enabled := range []bool{false, true} {
		cfg := serverConfig(backend.URL)
		cfg.HTTP.HTTP2Enable = enabled
		cert, key, roots := certificateFiles(t)
		cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
		s := newTestServer(t, cfg)
		if (s.h2Base != nil) != enabled {
			t.Fatal("HTTP/2 handler registration does not match configuration")
		}
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		for _, target := range []string{"http://" + s.HTTPAddress().String(), "https://" + s.TLSAddress().String()} {
			response, err := client.Get(target + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(body) != "ok" || response.Header.Get("Alt-Svc") != "" {
				t.Fatalf("HTTP(S) forwarding failed or advertised unsupported protocols: %+v %q %v", response, body, err)
			}
			wantProtocol := 1
			if enabled && response.TLS != nil {
				wantProtocol = 2
			}
			if response.ProtoMajor != wantProtocol {
				t.Fatalf("HTTP2=%t negotiated %s", enabled, response.Proto)
			}
		}
		for _, protocol := range []string{"h2", "h3"} {
			if protocol == "h2" && enabled {
				continue
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.TLSAddress().String(), &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{protocol}})
			if err == nil {
				conn.Close()
				t.Fatalf("negotiated disabled protocol %s", protocol)
			}
		}
	}
}

func TestIdleHTTPAndHTTPSKeepaliveConnectionsClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer backend.Close()
	cfg := serverConfig(backend.URL)
	cfg.HTTP.IdleTimeout = 150 * time.Millisecond
	cert, key, roots := certificateFiles(t)
	cfg.TLS.Enabled, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile = true, cert, key
	s := newTestServer(t, cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, secure := range []bool{false, true} {
		var conn net.Conn
		var err error
		if secure {
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.TLSAddress().String(), &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"http/1.1"}})
		} else {
			conn, err = net.DialTimeout("tcp", s.HTTPAddress().String(), time.Second)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for range 2 {
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 204 || response.Close {
				t.Fatal("active HTTP(S) keepalive did not remain usable")
			}
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := reader.ReadByte(); err != io.EOF {
			t.Fatalf("secure=%t idle connection did not close within timeout: %v", secure, err)
		}
	}
}
