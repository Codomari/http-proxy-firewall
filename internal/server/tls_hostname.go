package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"

	"http-proxy-firewall/internal/config"

	"github.com/valyala/fasthttp"
)

// A TLS handshake needs a certificate before an HTTP status can be sent. This
// in-memory, self-signed certificate is used only for clients that omit SNI. It
// never reaches ACME, the certificate cache, or the manual certificate list.
// Clients enforcing certificate trust can reject it before receiving the 409.
type hostnameRequiredCertificate struct {
	mu          sync.Mutex
	certificate *tls.Certificate
}

func (fallback *hostnameRequiredCertificate) get() (*tls.Certificate, error) {
	fallback.mu.Lock()
	defer fallback.mu.Unlock()
	now := time.Now()
	if pair := fallback.certificate; pair != nil && pair.Leaf.NotAfter.After(now.Add(time.Hour)) {
		return pair, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Hostname required"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	fallback.certificate = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return fallback.certificate, nil
}

func serveTLSHostnameRequired(ctx *fasthttp.RequestCtx, country string) {
	page := statusPageForCountry(country)
	ctx.Response.Reset()
	ctx.Response.SetStatusCode(fasthttp.StatusConflict)
	ctx.Response.Header.SetServer(config.ServerName)
	ctx.Response.Header.SetContentType("text/html; charset=utf-8")
	ctx.Response.Header.Set("Content-Language", page.language)
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Content-Security-Policy", conflictCSP)
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("Referrer-Policy", "no-referrer")
	ctx.Response.Header.SetConnectionClose()
	ctx.Response.SetBodyString(page.tlsHostnameRequired)
	ctx.Response.SkipBody = ctx.Request.Header.IsHead()
}
