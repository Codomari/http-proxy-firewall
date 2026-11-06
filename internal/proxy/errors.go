package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/valyala/fasthttp"
)

func retryUpstreamRequest(request *fasthttp.Request, _ int, err error) (bool, bool) {
	// Only replay empty GET/HEAD requests, before a response has been forwarded.
	// fasthttp closes the failed connection before invoking this callback, and
	// passes raw io.EOF here before converting it to ErrConnectionClosed.
	safe := (request.Header.IsGet() || request.Header.IsHead()) && len(request.Body()) == 0
	transient := errors.Is(err, io.EOF) || errors.Is(err, fasthttp.ErrConnectionClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
	return false, safe && transient
}

// Use fixed reasons rather than raw errors: parser errors and custom dialers
// can include response headers, credentials or other private upstream data.
func upstreamErrorReason(err error) string {
	var neterr net.Error
	var dns *net.DNSError
	var smallBuffer *fasthttp.ErrSmallBuffer
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.Is(err, fasthttp.ErrNoFreeConns):
		return "pool_exhausted"
	case errors.Is(err, fasthttp.ErrTimeout) || (errors.As(err, &neterr) && neterr.Timeout()):
		return "timeout"
	case errors.Is(err, io.EOF) || errors.Is(err, fasthttp.ErrConnectionClosed):
		return "connection_closed"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return "network_unreachable"
	case errors.As(err, &dns):
		return "dns_error"
	case errors.As(err, &smallBuffer):
		return "response_headers_too_large"
	case errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalidCertificate):
		return "tls_certificate_error"
	case errors.As(err, &recordHeader) || errors.As(err, &alert):
		return "tls_error"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, errUnexpectedUpgradeProtocol):
		return "invalid_upgrade_response"
	default:
		return "upstream_error"
	}
}
