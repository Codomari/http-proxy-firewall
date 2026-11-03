package observability

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

const (
	ResponsePreviewLimit    = 16 << 10
	BinaryResponseBodyLimit = 4 << 10
)

type CapturedHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CapturedResponse struct {
	Status        int              `json:"status"`
	Headers       []CapturedHeader `json:"headers"`
	Bytes         uint64           `json:"bytes"`
	Body          string           `json:"body"`
	BodyEncoding  string           `json:"body_encoding"`
	BodyTruncated bool             `json:"body_truncated"`
	BodyOmitted   string           `json:"body_omitted,omitempty"`
	Error         string           `json:"error,omitempty"`
}

type responseCaptureKey struct{}

// ResponseCapture owns copies only; streamed transfers can outlive Fiber's
// pooled context. Disabled captures add only a context lookup to stream setup.
type ResponseCapture struct {
	mu                         sync.Mutex
	started                    time.Time
	streamed, prepared, closed bool
	finished                   bool
	jsonBody                   bool
	preview                    []byte
	response                   CapturedResponse
	finish                     func(time.Duration, CapturedResponse)
}

func CaptureResponse(c fiber.Ctx, started time.Time, finish func(time.Duration, CapturedResponse)) *ResponseCapture {
	capture := &ResponseCapture{started: started, finish: finish}
	c.Locals(responseCaptureKey{}, capture)
	return capture
}

// WrapResponseStream must run before SetBodyStream: replacing an attached
// fasthttp stream closes it. Producers call this even when capture is disabled.
func WrapResponseStream(c fiber.Ctx, reader io.Reader) io.Reader {
	capture, ok := c.Locals(responseCaptureKey{}).(*ResponseCapture)
	if !ok || reader == nil {
		return reader
	}
	capture.mu.Lock()
	capture.streamed = true
	capture.mu.Unlock()
	return &capturedResponseStream{reader: reader, capture: capture}
}

// Prepare snapshots the final response after downstream middleware and error
// handling. Buffered responses finish here; streams finish on close.
func (capture *ResponseCapture) Prepare(c fiber.Ctx) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.response.Status = c.Response().StatusCode()
	mediaType, _, err := mime.ParseMediaType(string(c.Response().Header.ContentType()))
	capture.jsonBody = err == nil && strings.EqualFold(mediaType, "application/json")
	capture.response.Headers = []CapturedHeader{}
	buffered := !c.Response().IsBodyStream()
	bodyAllowed := capture.response.Status >= 200 && capture.response.Status != 204 && capture.response.Status != 304
	var header fasthttp.ResponseHeader
	c.Response().Header.CopyTo(&header)
	if name := c.App().Config().ServerHeader; name != "" {
		// The proxy's outer HTTP handler enforces this configured server name.
		header.SetServer(name)
	}
	if buffered && bodyAllowed {
		body := c.Response().Body()
		// fasthttp derives buffered Content-Length at serialization time. Match
		// that value in the snapshot without mutating the outgoing response.
		if !c.Response().SkipBody || len(body) > 0 {
			header.SetContentLength(len(body))
		}
		if !capture.streamed && !c.Response().SkipBody && !c.Request().Header.IsHead() {
			capture.record(body)
		}
	}
	// Serialize the copied header to include generated defaults and honor the
	// same bodyless-status rules as fasthttp's wire response.
	for _, line := range strings.Split(string(header.Header()), "\r\n")[1:] {
		if name, value, ok := strings.Cut(line, ": "); ok {
			capture.response.Headers = append(capture.response.Headers, CapturedHeader{Name: name, Value: value})
		}
	}
	capture.prepared = true
	capture.complete()
}

func (capture *ResponseCapture) record(data []byte) {
	capture.response.Bytes += uint64(len(data))
	if !capture.jsonBody {
		return
	}
	capture.preview = append(capture.preview, data[:min(len(data), ResponsePreviewLimit-len(capture.preview))]...)
}

// All callers hold mu. The completion callback receives owned values only.
func (capture *ResponseCapture) complete() {
	if capture.finished || !capture.prepared || (capture.streamed && !capture.closed) {
		return
	}
	capture.finished = true
	capture.response.BodyTruncated = capture.response.Bytes > uint64(len(capture.preview))
	capture.response.BodyEncoding = "utf-8"
	if !capture.jsonBody {
		capture.response.BodyOmitted = "Response Content-Type is not application/json"
		capture.response.BodyTruncated = false
		capture.finish(time.Since(capture.started), capture.response)
		return
	}
	text := utf8.Valid(capture.preview)
	for _, b := range capture.preview {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' || b == 0x7f {
			text = false
			break
		}
	}
	if text {
		capture.response.Body = string(capture.preview)
	} else {
		capture.response.BodyEncoding = "base64"
		if capture.response.Bytes > BinaryResponseBodyLimit {
			capture.response.BodyOmitted = "Binary body exceeds the 4 KiB capture limit"
			capture.response.BodyTruncated = false
		} else {
			capture.response.Body = base64.StdEncoding.EncodeToString(capture.preview)
		}
	}
	capture.finish(time.Since(capture.started), capture.response)
}

type capturedResponseStream struct {
	reader  io.Reader
	capture *ResponseCapture
	once    sync.Once
	err     error
}

func (stream *capturedResponseStream) Read(buffer []byte) (int, error) {
	n, err := stream.reader.Read(buffer)
	stream.capture.mu.Lock()
	defer stream.capture.mu.Unlock()
	stream.capture.record(buffer[:n])
	if err != nil && !errors.Is(err, io.EOF) {
		stream.capture.response.Error = strings.Clone(err.Error())
	}
	return n, err
}

// Implement only CloseWithError; fasthttp calls Close first when both exist,
// which would hide downstream failures from the upstream connection owner.
func (stream *capturedResponseStream) CloseWithError(writeError error) error {
	stream.once.Do(func() {
		if closer, ok := stream.reader.(fasthttp.ReadCloserWithError); ok {
			stream.err = closer.CloseWithError(writeError)
		} else if closer, ok := stream.reader.(io.Closer); ok {
			stream.err = closer.Close()
		}
		stream.capture.mu.Lock()
		defer stream.capture.mu.Unlock()
		if err := errors.Join(writeError, stream.err); err != nil {
			stream.capture.response.Error = err.Error()
		}
		stream.capture.closed = true
		stream.capture.complete()
	})
	return stream.err
}
