package observability

import (
	"encoding/base64"

	"github.com/gofiber/fiber/v3"
)

const RequestBodyLimit = 4 << 10

type CapturedRequestBody struct {
	Bytes        uint64 `json:"bytes"`
	BytesKnown   bool   `json:"bytes_known"`
	Body         string `json:"body"`
	BodyEncoding string `json:"body_encoding"`
	BodyOmitted  string `json:"body_omitted,omitempty"`
}

type requestCaptureKey struct{}

// CaptureRequestBody copies a buffered body before downstream mutation. Streams
// are observed by body inspection; debug logging never reads or drains them.
func CaptureRequestBody(c fiber.Ctx) *CapturedRequestBody {
	request := c.Request()
	length := request.Header.ContentLength()
	body := &CapturedRequestBody{BodyEncoding: "base64", BytesKnown: length >= 0}
	if length >= 0 {
		body.Bytes = uint64(length)
	}
	c.Locals(requestCaptureKey{}, body)
	if !request.IsBodyStream() {
		RecordRequestBody(c, request.Body(), true)
	} else if length > RequestBodyLimit {
		body.BodyOmitted = "Request body exceeds the 4 KiB capture limit"
	} else {
		body.BodyOmitted = "Request body was not read before the request completed"
	}
	return body
}

// RecordRequestBody must run before the firewall releases or resets its buffer.
// Only an active debug capture allocates, and oversized bodies are never encoded.
func RecordRequestBody(c fiber.Ctx, data []byte, complete bool) {
	body, ok := c.Locals(requestCaptureKey{}).(*CapturedRequestBody)
	if !ok {
		return
	}
	body.Bytes, body.BytesKnown = uint64(len(data)), complete
	body.Body, body.BodyOmitted = "", ""
	if len(data) > RequestBodyLimit {
		body.BodyOmitted = "Request body exceeds the 4 KiB capture limit"
	} else if !complete {
		body.BodyOmitted = "Request body was not completely read"
	} else {
		body.Body = base64.StdEncoding.EncodeToString(data)
	}
}
