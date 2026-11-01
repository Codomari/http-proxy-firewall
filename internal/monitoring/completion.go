package monitoring

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

type completionKey struct{}

// completion deliberately retains no Fiber context, request, response, or
// request-backed strings. It may outlive pooled contexts during streams/tunnels.
type completion struct {
	registry     *Registry
	host         *hostRecord
	once         sync.Once
	asynchronous atomic.Bool
}

func (c *completion) finish(status int, bytesOut uint64) {
	c.once.Do(func() {
		if c.host != nil {
			c.host.bytesOut.Add(bytesOut)
			markSeen(c.host, time.Now())
		}
		if status >= 400 && status < 500 {
			c.registry.totals.rejected.Add(1)
			if c.host != nil {
				c.host.rejected.Add(1)
			}
		}
		if status >= 500 && status < 600 {
			c.registry.totals.errors5xx.Add(1)
			if c.host != nil {
				c.host.errors5xx.Add(1)
			}
		}
		// Publish completion only after all byte/status counters are committed.
		if c.host != nil {
			c.host.inflight.Add(^uint64(0))
		}
		c.registry.totals.inflight.Add(^uint64(0))
	})
}

func ignoreCompletion(int, uint64) {}

// Completion claims transfer ownership for an upgraded connection. Invoke the
// returned idempotent callback when the tunnel closes. It owns only counters and
// remains safe after the HTTP context has returned to its pool.
func Completion(c fiber.Ctx) func(status int, bytesOut uint64) {
	if owned, ok := c.Locals(completionKey{}).(*completion); ok {
		owned.asynchronous.Store(true)
		return owned.finish
	}
	return ignoreCompletion
}

// AddBytesIn records bytes actually consumed by body inspection, including
// partial rejected reads. A claimed Content-Length is never counted as traffic.
func AddBytesIn(c fiber.Ctx, bytes uint64) {
	if owned, ok := c.Locals(completionKey{}).(*completion); ok && owned.host != nil {
		owned.host.bytesIn.Add(bytes)
	}
}

// WrapStream must be called by the producer BEFORE its initial SetBodyStream.
// Replacing an already attached fasthttp stream would close it prematurely.
// Disabled monitoring returns the original reader without another wrapper.
func WrapStream(c fiber.Ctx, reader io.Reader, status int) io.Reader {
	owned, ok := c.Locals(completionKey{}).(*completion)
	if !ok || reader == nil {
		return reader
	}
	owned.asynchronous.Store(true)
	return &responseStream{reader: reader, completion: owned, status: status}
}

type responseStream struct {
	reader     io.Reader
	completion *completion
	status     int
	bytes      atomic.Uint64
	once       sync.Once
	closeError error
}

func (s *responseStream) Read(buffer []byte) (int, error) {
	n, err := s.reader.Read(buffer)
	if n > 0 {
		s.bytes.Add(uint64(n))
	}
	return n, err
}

// Do not also implement io.Closer: fasthttp calls Close before CloseWithError
// for readers implementing both, which would discard a downstream write error.
func (s *responseStream) CloseWithError(writeError error) error {
	s.once.Do(func() {
		defer s.completion.finish(s.status, s.bytes.Load())
		if closer, ok := s.reader.(fasthttp.ReadCloserWithError); ok {
			s.closeError = closer.CloseWithError(writeError)
		} else if closer, ok := s.reader.(io.Closer); ok {
			s.closeError = closer.Close()
		}
	})
	return s.closeError
}
