package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"http-proxy-firewall/internal/admin"
)

func (s *Server) CanRequestCertificate() bool { return s.manager != nil }

func (s *Server) hasUsableCachedCertificate(ctx context.Context, host string) bool {
	if s.manager == nil || s.manager.Cache == nil {
		return false
	}
	host, err := certificateHostname(host)
	if err != nil {
		return false
	}
	now := time.Now()
	if usable, found := s.usableCerts.Get(host, now); found {
		return usable
	}
	for _, key := range []string{host, host + "+rsa"} {
		data, err := s.manager.Cache.Get(ctx, key)
		if err != nil || len(data) > 64<<10 {
			continue
		}
		pair, err := tls.X509KeyPair(data, data)
		if err != nil || len(pair.Certificate) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) && leaf.VerifyHostname(host) == nil {
			s.usableCerts.Set(host, true, minTime(now.Add(time.Minute), leaf.NotAfter), now)
			return true
		}
	}
	s.usableCerts.Set(host, false, now.Add(5*time.Second), now)
	return false
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Server) CertificateEntries() ([]admin.CertificateEntry, error) {
	entries := []admin.CertificateEntry{}
	appendFile := func(path, host, source string) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 64<<10 {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		if err != nil {
			return err
		}
		if len(data) > 64<<10 {
			return nil
		}
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || cert.IsCA {
				continue
			}
			names := append([]string{}, cert.DNSNames...)
			for _, ip := range cert.IPAddresses {
				names = append(names, ip.String())
			}
			if host == "" && len(names) > 0 {
				host = names[0]
			}
			entries = append(entries, admin.CertificateEntry{Hostname: host, Names: names, Issuer: cert.Issuer.String(), NotBefore: cert.NotBefore, Expires: cert.NotAfter, Source: source})
			break
		}
		return nil
	}
	if s.cfg.TLS.CertificateFile != "" {
		if err := appendFile(s.cfg.TLS.CertificateFile, "", "static"); err != nil {
			return nil, err
		}
	} else {
		files, err := os.ReadDir(s.cfg.TLS.CacheDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, file := range files {
			if file.Type()&os.ModeSymlink != 0 || file.IsDir() || strings.HasSuffix(file.Name(), "+token") {
				continue
			}
			host := strings.TrimSuffix(file.Name(), "+rsa")
			if _, err := certificateHostname(host); err != nil {
				continue
			}
			if len(entries) >= certificateHostLimit {
				break
			}
			if err := appendFile(filepath.Join(s.cfg.TLS.CacheDir, file.Name()), host, "automatic"); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Hostname < entries[j].Hostname })
	return entries, nil
}

func (s *Server) CertificateRequests() []admin.CertificateRequest {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	requests := make([]admin.CertificateRequest, 0, len(s.certRequests))
	for _, request := range s.certRequests {
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].Started.After(requests[j].Started) })
	return requests
}

func (s *Server) RequestCertificate(raw string) error {
	if !s.CanRequestCertificate() {
		return errors.New("automatic TLS certificates are disabled")
	}
	host, err := certificateHostname(raw)
	if err != nil {
		return err
	}
	if s.certGuard.behindCloudflare != nil && s.certGuard.behindCloudflare(host) {
		return errCertificateCloudflare
	}
	if err := hostPolicy(s.cfg.TLS.Hosts)(context.Background(), host); err != nil {
		return errors.New("hostname is not allowed by PF_TLS_HOSTS")
	}
	s.certGuard.mu.Lock()
	blocked := s.certGuard.blacklist[host].After(s.certGuard.now())
	s.certGuard.mu.Unlock()
	if blocked {
		return errors.New("remove this hostname from BLACKLIST before requesting its certificate")
	}
	s.mu.Lock()
	stopping := s.stopping
	s.mu.Unlock()
	if stopping {
		return errors.New("server is stopping")
	}
	s.certMu.Lock()
	if previous := s.certRequests[host]; previous.Status == "requesting" {
		s.certMu.Unlock()
		return nil
	}
	now := time.Now().UTC()
	running := 0
	for host, request := range s.certRequests {
		if request.Status == "requesting" {
			running++
		} else if request.Started.Before(now.Add(-time.Hour)) {
			delete(s.certRequests, host)
		}
	}
	_, existing := s.certRequests[host]
	if running >= 16 || !existing && len(s.certRequests) >= 1000 {
		s.certMu.Unlock()
		return errors.New("certificate request queue is full")
	}
	s.certRequests[host] = admin.CertificateRequest{Hostname: host, Status: "requesting", Started: now}
	s.certMu.Unlock()
	go func() {
		err := s.certGuard.check(context.Background(), host)
		if err == nil && s.certIssue != nil {
			err = s.certIssue(host)
		} else if err == nil {
			_, err = s.manager.GetCertificate(&tls.ClientHelloInfo{ServerName: host, SupportedCurves: []tls.CurveID{tls.CurveP256}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
		}
		finished := time.Now().UTC()
		s.certMu.Lock()
		request := s.certRequests[host]
		request.Finished = &finished
		request.Status = "issued"
		if err != nil {
			request.Status = "failed"
			request.Message = "Certificate request failed. Check BLACKLIST and service logs."
			s.logger.Warn("manual certificate request failed", "hostname", host, "error_type", fmt.Sprintf("%T", err))
		}
		s.certRequests[host] = request
		s.certMu.Unlock()
	}()
	return nil
}
