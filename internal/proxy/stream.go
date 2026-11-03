package proxy

import (
	"bytes"
	"io"
	"sync"

	"http-proxy-firewall/internal/monitoring"
	"http-proxy-firewall/internal/observability"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

// responseStream retains only a pooled response and its upstream stream. The
// admission slot spans the complete transfer, including slow downstream reads.
type responseStream struct {
	io.Reader
	response *fasthttp.Response
	release  func()
	once     sync.Once
}

func forwardResponse(c fiber.Ctx, response *fasthttp.Response, release func()) {
	response.Header.CopyTo(&c.Response().Header)
	stripResponseHopHeaders(&c.Response().Header)
	c.Response().SkipBody = response.SkipBody
	body := response.BodyStream()
	if body == nil {
		body = bytes.NewReader(response.Body())
	}
	stream := &responseStream{Reader: body, response: response, release: release}
	c.Response().SetBodyStream(observability.WrapResponseStream(c, monitoring.WrapStream(c, stream, response.StatusCode())), response.Header.ContentLength())
	// Keep ordinary headers in the existing bounded writer buffer so small
	// bodies share one write. Unknown-length streams and SSE need prompt headers.
	mediaType, _, _ := bytes.Cut(response.Header.ContentType(), []byte(";"))
	c.Response().ImmediateHeaderFlush = response.Header.ContentLength() < 0 || bytes.EqualFold(bytes.TrimSpace(mediaType), []byte("text/event-stream"))
}

func (s *responseStream) Close() error { return s.CloseWithError(nil) }
func (s *responseStream) CloseWithError(err error) error {
	s.once.Do(func() {
		// The client's release callback rechecks this flag. A downstream write
		// failure must discard the upstream connection rather than reuse it.
		if err != nil {
			s.response.Header.SetConnectionClose()
		}
		fasthttp.ReleaseResponse(s.response)
		s.release()
	})
	return nil
}
