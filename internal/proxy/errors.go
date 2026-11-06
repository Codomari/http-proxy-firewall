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
	// fasthttp closes a failed connection before returning its error.
	safe := (request.Header.IsGet() || request.Header.IsHead()) && len(request.Body()) == 0
	transient := errors.Is(err, io.EOF) || errors.Is(err, fasthttp.ErrConnectionClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
	return false, safe && transient
}

// SetRequestRetryTimes applies to new requests on every upstream route. Requests
// already in progress retain their original retry budget.
func (h *Handler) SetRequestRetryTimes(times int) {
	if times < 0 {
		return
	}
	h.retryTimes.Store(int64(times))
	for _, route := range h.routes {
		route.SetRequestRetryTimes(times)
	}
}

func (h *Handler) doRequest(request *fasthttp.Request, response *fasthttp.Response) error {
	retries := h.retryTimes.Load()
	for attempt := int64(0); ; attempt++ {
		err := h.client.Do(request, response)
		_, retry := retryUpstreamRequest(request, 0, err)
		if err == nil || !retry || attempt >= retries || h.closed.Load() {
			return err
		}
		// fasthttp already discarded the failed connection. Drop the remaining
		// idle sockets too, so the retry cannot consume another stale socket
		// from the same pool. Active requests keep their connections and the
		// existing MaxConns/admission limits still govern any replacement dial.
		h.client.CloseIdleConnections()
		response.Reset()
	}
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
