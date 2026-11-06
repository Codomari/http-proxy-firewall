package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/firewall"

	"github.com/gofiber/fiber/v3"
)

const (
	certificateBlacklistFile = ".certbot.blacklist"
	certificateBlacklistTTL  = 14 * 24 * time.Hour
	certificateProbeTimeout  = time.Second
	certificateProbeAttempts = 3
	certificateVerifiedTTL   = time.Minute
	certificateHostLimit     = 10000
	certificateProbeLimit    = 64
	dnsSignatureHeader       = "X-DNS-SIGNATURE"
)

var (
	errCertificateBlacklisted = errors.New("certificate hostname is blacklisted")
	errCertificateDNS         = errors.New("certificate hostname does not point to this server")
	errCertificateBusy        = errors.New("certificate hostname checks are at capacity")
	errCertificateCloudflare  = errors.New("automatic certificate requests are disabled for hostnames marked Behind CloudFlare")
)

type certificateProbe struct {
	done chan struct{}
	err  error
}

// One guard is shared by all certificate requests and the public HEAD route.
// Its bounded signature map is keyed by canonical hostname, never by client IP.
type certificateGuard struct {
	path             string
	file             string
	logger           *slog.Logger
	client           *http.Client
	lookup           func(context.Context, string, string) ([]netip.Addr, error)
	localIPs         func() ([]netip.Addr, error)
	behindCloudflare func(string) bool
	country          func(fiber.Ctx) string
	now              func() time.Time
	signatures       *cache.Cache[string, string]
	verified         *cache.Cache[string, bool]
	mu               sync.Mutex
	pending          map[string]*certificateProbe
	blacklist        map[string]time.Time
}

func newCertificateGuard(path, file string, logger *slog.Logger) (*certificateGuard, error) {
	if logger == nil {
		logger = slog.Default()
	}
	g := &certificateGuard{
		path: path, file: file, logger: logger, now: time.Now,
		lookup: net.DefaultResolver.LookupNetIP, localIPs: certificateLocalIPs,
		signatures: cache.New[string, string](certificateHostLimit),
		verified:   cache.New[string, bool](certificateHostLimit),
		pending:    make(map[string]*certificateProbe), blacklist: make(map[string]time.Time),
		client: &http.Client{
			Timeout:       certificateProbeTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 8 << 10,
				DialContext:           certificateProbeDialer().DialContext,
				ResponseHeaderTimeout: certificateProbeTimeout,
			},
		},
	}
	if err := g.loadBlacklist(); err != nil {
		return nil, fmt.Errorf("load certificate blacklist: %w", err)
	}
	return g, nil
}

func certificateHostname(raw string) (string, error) {
	host, err := firewall.CanonicalHostname(raw)
	if err != nil || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", errors.New("certificate hostname must be a DNS name")
	}
	hasLetter := false
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid certificate DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("invalid certificate DNS character")
			}
			hasLetter = hasLetter || ch >= 'a' && ch <= 'z'
		}
	}
	if !hasLetter {
		return "", errors.New("certificate hostname cannot contain only numbers")
	}
	return host, nil
}

func (g *certificateGuard) serve(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	if c.Request().Header.ContentLength() > 0 || len(c.Request().Header.Peek("Transfer-Encoding")) != 0 {
		c.Response().Header.SetConnectionClose()
		return c.SendStatus(fiber.StatusBadRequest)
	}
	if c.Method() != fiber.MethodHead {
		c.Set("Allow", "HEAD")
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}
	host, err := certificateHostname(string(c.Request().Header.Host()))
	if err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}
	now := g.now()
	g.mu.Lock()
	signature, ok := g.signatures.Get(host, now)
	if !ok {
		signature = rand.Text()
		g.signatures.Set(host, signature, now.Add(certificateVerifiedTTL), now)
	}
	g.mu.Unlock()
	c.Set(dnsSignatureHeader, signature)
	return c.SendStatus(fiber.StatusNoContent)
}

func (g *certificateGuard) check(ctx context.Context, raw string) (resultErr error) {
	host, err := certificateHostname(raw)
	if err != nil {
		return err
	}
	// Preserve errors.Is while keeping hostname context when TLS/ACME callers
	// report this error outside the guard's own structured log messages.
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("certificate guard for %s: %w", host, resultErr)
		}
	}()
	if g.behindCloudflare != nil && g.behindCloudflare(host) {
		return errCertificateCloudflare
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := g.now()
	g.mu.Lock()
	if until := g.blacklist[host]; until.After(now) {
		g.mu.Unlock()
		return fmt.Errorf("%w until %s", errCertificateBlacklisted, until.UTC().Format(time.RFC3339))
	}
	delete(g.blacklist, host)
	if _, ok := g.verified.Get(host, now); ok {
		g.mu.Unlock()
		return nil
	}
	if pending := g.pending[host]; pending != nil {
		g.mu.Unlock()
		select {
		case <-pending.done:
			return pending.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	g.pruneBlacklist(now)
	if len(g.pending) >= certificateProbeLimit || len(g.blacklist) >= certificateHostLimit {
		g.mu.Unlock()
		return errCertificateBusy
	}
	pending := &certificateProbe{done: make(chan struct{})}
	g.pending[host] = pending
	// A remote service cannot replay a signature left by an earlier HEAD.
	g.signatures.Set(host, "", now, now)
	g.mu.Unlock()

	err = g.probe(ctx, host)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err == nil {
		now = g.now()
		g.verified.Set(host, true, now.Add(certificateVerifiedTTL), now)
	} else if ctx.Err() == nil {
		until := g.now().Add(certificateBlacklistTTL)
		g.blacklist[host] = until
		if saveErr := g.saveBlacklist(); saveErr != nil {
			g.logger.Error("certificate blacklist could not be saved", "hostname", host, "error_type", fmt.Sprintf("%T", saveErr))
			err = errors.Join(err, errors.New("certificate blacklist persistence failed"))
		}
		g.logger.Warn("certificate hostname verification failed", "hostname", host, "blacklisted_until", until.UTC().Format(time.RFC3339))
	}
	pending.err = err
	delete(g.pending, host)
	close(pending.done)
	return err
}

func (g *certificateGuard) probe(ctx context.Context, host string) error {
	target := url.URL{Scheme: "http", Host: host, Path: g.path}
	for attempt := 0; attempt < certificateProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Bust intermediary caches without giving remote hosts the signature.
		target.RawQuery = "probe=" + rand.Text()
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
		if err != nil {
			return err
		}
		request.Header.Set("Cache-Control", "no-cache")
		response, err := g.client.Do(request)
		if err != nil {
			continue
		}
		_ = response.Body.Close()
		values := response.Header.Values(dnsSignatureHeader)
		if response.StatusCode < 200 || response.StatusCode >= 300 || len(values) != 1 || values[0] == "" {
			continue
		}
		signature, ok := g.signatures.Get(host, g.now())
		if ok && subtle.ConstantTimeCompare([]byte(signature), []byte(values[0])) == 1 {
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// HTTP timeouts and incorrect signatures can still be legitimate when a
	// local firewall or NAT prevents this server from reaching its public IP.
	lookupCtx, cancel := context.WithTimeout(ctx, certificateProbeTimeout)
	defer cancel()
	addresses, err := g.lookup(lookupCtx, "ip", host)
	if err != nil {
		return errCertificateDNS
	}
	local, err := g.localIPs()
	if err != nil {
		return errCertificateDNS
	}
	for _, address := range addresses {
		if !certificatePublicIP(address) {
			continue
		}
		for _, own := range local {
			if certificatePublicIP(own) && address.Unmap() == own.Unmap() {
				return nil
			}
		}
	}
	return errCertificateDNS
}

func certificateLocalIPs() ([]netip.Addr, error) {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(interfaces))
	for _, address := range interfaces {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil && certificatePublicIP(prefix.Addr()) {
			addresses = append(addresses, prefix.Addr().Unmap())
		}
	}
	return addresses, nil
}
