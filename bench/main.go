// Command benchmark runs only against the isolated local benchmark environment.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const originHeader = "X-Benchmark-Origin"
const originValue = "benchmark-upstream-v1"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: benchmark upstream|load|cert|check [flags]")
	}
	switch args[0] {
	case "upstream":
		return runUpstream(ctx, args[1:])
	case "load":
		return runLoad(ctx, args[1:])
	case "cert":
		return runCert(args[1:])
	case "check":
		return runCheck(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// Restrict load generation to loopback, private IP literals, and the named
// services in our isolated Compose network. Arbitrary internet names are denied.
func localTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("target must be a local HTTP(S) URL without userinfo")
	}
	host := strings.ToLower(u.Hostname())
	if host == "firewall" || host == "backend" || host == "localhost" {
		return u, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return nil, errors.New("load targets are restricted to firewall, backend, localhost, or private/loopback IP literals")
	}
	return u, nil
}

func runCheck(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	target := flags.String("url", "http://127.0.0.1:8081/ready", "local readiness URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	u, err := localTarget(*target)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness status %d", resp.StatusCode)
	}
	return nil
}

func runCert(args []string) error {
	flags := flag.NewFlagSet("cert", flag.ContinueOnError)
	certPath := flags.String("cert", "/certs/server.crt", "disposable certificate path")
	keyPath := flags.String("key", "/certs/server.key", "disposable private-key path")
	keyMode := flags.String("key-mode", "0600", "disposable key permissions (0644 only for isolated benchmark volumes)")
	reuse := flags.Bool("reuse", false, "keep an existing valid matching certificate/key pair")
	hosts := flags.String("hosts", "firewall,localhost,127.0.0.1,::1", "certificate SANs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	mode, err := strconv.ParseUint(*keyMode, 8, 32)
	if err != nil || (mode != 0600 && mode != 0644) {
		return errors.New("key mode must be 0600 or 0644")
	}
	if *reuse {
		pair, loadErr := tls.LoadX509KeyPair(*certPath, *keyPath)
		if loadErr == nil {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			valid := err == nil && !time.Now().Before(leaf.NotBefore) && time.Now().Before(leaf.NotAfter) && leaf.VerifyHostname("firewall") == nil
			if valid {
				for _, host := range strings.Split(*hosts, ",") {
					if host = strings.TrimSpace(host); host != "" && leaf.VerifyHostname(host) != nil {
						valid = false
						break
					}
				}
			}
			if valid {
				return certificatePermissions(*certPath, *keyPath, os.FileMode(mode))
			}
		}
		// Never silently rotate an existing pair while the running firewall may
		// still hold its old certificate. A missing pair is safe to initialize.
		_, certErr := os.Stat(*certPath)
		_, keyErr := os.Stat(*keyPath)
		if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
			return errors.New("existing benchmark certificate cannot be reused; recreate the benchmark containers and certificate volume")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Disposable proxy benchmark"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(48 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	for _, host := range strings.Split(*hosts, ",") {
		host = strings.TrimSpace(host)
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	for _, target := range []string{*certPath, *keyPath} {
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(*keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), os.FileMode(mode)); err != nil {
		return err
	}
	if err := os.WriteFile(*certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	return certificatePermissions(*certPath, *keyPath, os.FileMode(mode))
}

func certificatePermissions(certPath, keyPath string, mode os.FileMode) error {
	if err := os.Chmod(keyPath, mode); err != nil {
		return err
	}
	if err := os.Chmod(certPath, 0644); err != nil {
		return err
	}
	if mode == 0644 {
		for _, target := range []string{certPath, keyPath} {
			if err := os.Chmod(filepath.Dir(target), 0755); err != nil {
				return err
			}
		}
	}
	return nil
}
