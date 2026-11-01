package firewall

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	cve2026109618 "http-proxy-firewall/internal/firewall/cves/2026-109618"
	cve2026109619 "http-proxy-firewall/internal/firewall/cves/2026-109619"
	"http-proxy-firewall/internal/monitoring"
)

// inspect returns a cleanup function that must span c.Next. On rejection it
// sends the response itself; the caller observes its >=400 status and stops.
func (e *Engine) inspect(c fiber.Ctx) (func(), error) {
	req := c.Request()
	allowsBody := requestMethodAllowsBody(string(req.Header.Method()))
	length := int64(req.Header.ContentLength())
	if !allowsBody && length > 0 {
		return nil, e.reject(c, fiber.StatusBadRequest, errors.New("body is not allowed for this HTTP method"), nil)
	}
	if length > e.limits.MaxBodyBytes {
		return nil, e.reject(c, fiber.StatusRequestEntityTooLarge, cve2026109618.ErrBodyTooLarge, nil)
	}
	if err, status := validateBodyHeaders(&req.Header); err != nil {
		return nil, e.reject(c, status, err, nil)
	}
	contentType := string(req.Header.ContentType())
	// Header-only parsing rejects malformed types before buffering. The hardened
	// checker independently validates body framing and all MIME ambiguities.
	mediaType, params, err := parseContentType(contentType)
	if err != nil {
		return nil, e.reject(c, fiber.StatusBadRequest, err, nil)
	}
	reservation := e.limits.MaxBodyBytes + 1
	if allowsBody && length >= 0 {
		reservation = length
		if length > 0 {
			reservation++ // A known-length body needs only its own overflow probe.
		}
	} else if !allowsBody {
		reservation = 1
		if length == 0 {
			reservation = 0
		}
	}
	stream := req.BodyStream()
	if stream == nil && len(req.Body()) == 0 {
		reservation = 0
	}
	if !e.budget.acquire(reservation) {
		return nil, e.reject(c, fiber.StatusServiceUnavailable, errors.New("request body memory budget exhausted"), nil)
	}
	release := func() {
		// Do not let pooled request objects retain an inspected large body.
		req.ReleaseBody(64 << 10)
		req.ResetBody()
		e.budget.release(reservation)
	}
	var body []byte
	if stream != nil {
		// Empty bodies retain no inspection buffer. A one-byte temporary probe
		// still detects a body supplied by a custom zero-length stream.
		readLimit := max(int(reservation), 1)
		body, err = readBounded(stream, readLimit, int(length))
		_ = req.CloseBodyStream()
	} else {
		body = req.Body()
	}
	if e.trackInput && len(body) > 0 {
		monitoring.AddBytesIn(c, uint64(len(body)))
	}
	if !allowsBody && len(body) > 0 {
		return release, e.reject(c, fiber.StatusBadRequest, errors.New("body is not allowed for this HTTP method"), nil)
	}
	if int64(len(body)) > e.limits.MaxBodyBytes {
		return release, e.reject(c, fiber.StatusRequestEntityTooLarge, cve2026109618.ErrBodyTooLarge, nil)
	}
	if err != nil || (length >= 0 && length != int64(len(body))) {
		return release, e.reject(c, fiber.StatusBadRequest, errors.New("failed to read complete request body"), nil)
	}
	if len(body) == 0 {
		body = nil
		e.budget.release(reservation)
		reservation = 0
	}
	fields, err := cve2026109618.Check(body, contentType, e.limits)
	if err != nil {
		status := fiber.StatusBadRequest
		if errors.Is(err, cve2026109618.ErrBodyTooLarge) || errors.Is(err, cve2026109618.ErrInputLimit) {
			status = fiber.StatusRequestEntityTooLarge
		}
		return release, e.reject(c, status, err, body)
	}
	if err := cve2026109619.Check(fields, e.uploadNames); err != nil {
		return release, e.reject(c, fiber.StatusForbidden, err, nil)
	}
	if mediaType == "multipart/form-data" {
		req.Header.SetContentType(mime.FormatMediaType(mediaType, map[string]string{"boundary": params["boundary"]}))
	}
	if stream != nil {
		// Our stream buffer owns its storage. A prebuffered fasthttp body already
		// belongs to req and must not be returned to its pool and reattached raw.
		req.SetBodyRaw(body)
	}
	req.Header.Del("Transfer-Encoding")
	req.Header.SetContentLength(len(body))
	return release, nil
}

func requestMethodAllowsBody(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH"
}

func parseContentType(value string) (string, map[string]string, error) {
	if value == "" {
		return "", nil, nil
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || (strings.HasPrefix(mediaType, "multipart/") && (mediaType != "multipart/form-data" || params["boundary"] == "")) {
		return "", nil, cve2026109618.ErrMalformed
	}
	return mediaType, params, nil
}

func validateBodyHeaders(header *fasthttp.RequestHeader) (error, int) {
	contentTypes := 0
	var encodingError bool
	visit := func(key, value []byte) bool {
		if bytes.EqualFold(key, []byte("Content-Type")) {
			contentTypes++
		}
		if bytes.EqualFold(key, []byte("Content-Encoding")) && !strings.EqualFold(strings.TrimSpace(string(value)), "identity") {
			encodingError = true
		}
		return true
	}
	if len(header.RawHeaders()) > 0 {
		// fasthttp's special Content-Type field is last-value-wins. Reparse
		// preserved raw headers to catch duplicates before that information is lost.
		header.AllInOrder()(visit)
	} else {
		header.All()(visit)
	}
	if contentTypes > 1 {
		return cve2026109618.ErrMalformed, fiber.StatusBadRequest
	}
	if encodingError {
		return errors.New("unsupported request content encoding"), fiber.StatusUnsupportedMediaType
	}
	return nil, 0
}

// readBounded caps both length and capacity. Unlike io.ReadAll, its final growth
// cannot overshoot the reserved byte budget. It reads at most limit bytes.
func readBounded(reader io.Reader, limit, knownLength int) ([]byte, error) {
	if limit == 0 {
		return nil, nil
	}
	initial := 32 << 10
	if knownLength >= 0 && knownLength < limit {
		initial = knownLength + 1
	}
	if initial > limit {
		initial = limit
	}
	body := make([]byte, 0, initial)
	emptyReads := 0
	for len(body) < limit {
		if len(body) == cap(body) {
			next := cap(body) + min(cap(body), limit-cap(body))
			grown := make([]byte, len(body), next)
			copy(grown, body)
			body = grown
		}
		n, err := reader.Read(body[len(body):cap(body)])
		body = body[:len(body)+n]
		if err == io.EOF {
			return body, nil
		}
		if err != nil {
			return body, err
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return body, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
	return body, nil
}

func (e *Engine) reject(c fiber.Ctx, status int, err error, body []byte) error {
	if e.logger.Enabled(c.Context(), slog.LevelWarn) {
		reason := reasonForRejection(status, err)
		if emit, suppressed := e.rejectionLogs.allow(reason, e.now()); emit {
			e.logRejection(c, status, err, body, reason, suppressed)
		}
	}
	// Do not drain an untrusted rejected upload just to reuse its connection.
	c.RequestCtx().SetConnectionClose()
	return c.SendStatus(status)
}

func (e *Engine) logRejection(c fiber.Ctx, status int, err error, body []byte, reason rejectionReason, suppressed uint64) {
	attributes := []any{
		"client_ip", ClientIP(c), "status", status, "error", err,
		"reason", rejectionReasonNames[reason], "suppressed", suppressed,
	}
	if reason == rejectionMalformed && len(body) > 0 {
		serialized, truncated := serializedFormDataChunk(body)
		// QuoteToASCII produced a valid Go string literal. Decode it before
		// passing it to slog so TextHandler escapes the value exactly once.
		excerpt, _ := strconv.Unquote(serialized)
		attributes = append(attributes, "form_data", excerpt, "form_data_truncated", truncated)
	}
	e.logger.WarnContext(c.Context(), "request rejected", attributes...)
}

// Bound serialized output, including quotes and escapes, to 30 bytes.
func serializedFormDataChunk(body []byte) (string, bool) {
	const maxChars = 30
	var chunk strings.Builder
	chunk.Grow(maxChars)
	chunk.WriteByte('"')
	for len(body) > 0 {
		_, size := utf8.DecodeRune(body)
		escaped := strconv.QuoteToASCII(string(body[:size]))
		escaped = escaped[1 : len(escaped)-1]
		if chunk.Len()+len(escaped)+1 > maxChars {
			chunk.WriteByte('"')
			return chunk.String(), true
		}
		chunk.WriteString(escaped)
		body = body[size:]
	}
	chunk.WriteByte('"')
	return chunk.String(), false
}
