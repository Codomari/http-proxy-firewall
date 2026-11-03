package observability

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func TestResponseCaptureBufferedPreviewAndBodylessResponses(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, encoding string
		status                       int
	}{
		{"text", "GET", "<script>alert(1)</script>\n] | quoted \"body\"", "utf-8", 200},
		{"large", "GET", strings.Repeat("a", ResponsePreviewLimit+100), "utf-8", 403},
		{"binary", "GET", "\x00\xff\x01", "base64", 200},
		{"head", "HEAD", "unsent body", "utf-8", 200},
		{"no-content", "GET", "", "utf-8", 204},
		{"not-modified", "GET", "", "utf-8", 304},
	} {
		t.Run(tc.name, func(t *testing.T) {
			completed := make(chan CapturedResponse, 1)
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error {
				capture := CaptureResponse(c, time.Now().Add(-time.Millisecond), func(duration time.Duration, response CapturedResponse) {
					if duration < time.Millisecond {
						t.Error("duration omitted request processing")
					}
					completed <- response
				})
				err := c.Next()
				capture.Prepare(c)
				return err
			})
			app.Use(func(c fiber.Ctx) error {
				c.Response().Header.Add("Set-Cookie", "one=1")
				c.Response().Header.Add("Set-Cookie", "two=2")
				c.Set("Content-Type", "application/json; charset=utf-8")
				return c.Status(tc.status).SendString(tc.body)
			})
			response, err := app.Test(httptest.NewRequest(tc.method, "http://example.com/", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.body
			if tc.method == "HEAD" {
				want = ""
			}
			got := <-completed
			if string(body) != want || got.Status != response.StatusCode || got.Bytes != uint64(len(want)) || got.BodyEncoding != tc.encoding {
				t.Fatalf("response changed or capture wrong: actual=%q captured=%+v", body, got)
			}
			preview := []byte(want[:min(len(want), ResponsePreviewLimit)])
			if tc.encoding == "base64" {
				preview = []byte(base64.StdEncoding.EncodeToString(preview))
			}
			if got.Body != string(preview) || got.BodyTruncated != (len(want) > ResponsePreviewLimit) {
				t.Fatal("incorrect preview or truncation flag")
			}
			var cookies []string
			capturedLength := ""
			for _, header := range got.Headers {
				if strings.EqualFold(header.Name, "Set-Cookie") {
					cookies = append(cookies, header.Value)
				}
				if strings.EqualFold(header.Name, "Content-Length") {
					capturedLength = header.Value
				}
			}
			if response.Header.Get("Content-Length") != "" && capturedLength != strconv.FormatInt(response.ContentLength, 10) {
				t.Fatalf("captured Content-Length=%s actual=%d", capturedLength, response.ContentLength)
			}
			if len(cookies) != 2 || cookies[0] != "one=1" || cookies[1] != "two=2" {
				t.Fatalf("duplicate response cookies lost: %q", cookies)
			}
		})
	}
}

type captureTestStream struct {
	io.Reader
	closed int
	err    error
}

func (stream *captureTestStream) CloseWithError(err error) error {
	stream.closed++
	stream.err = err
	return nil
}

func TestResponseCaptureStreamWaitsForCloseAndPreservesWriteErrors(t *testing.T) {
	var ctx fasthttp.RequestCtx
	ctx.Request.SetRequestURI("http://example.com/")
	app := fiber.New()
	c := app.AcquireCtx(&ctx)
	defer app.ReleaseCtx(c)
	var completed int
	var result CapturedResponse
	capture := CaptureResponse(c, time.Now(), func(_ time.Duration, response CapturedResponse) {
		completed++
		result = response
	})
	data := bytes.Repeat([]byte("x"), ResponsePreviewLimit+100)
	source := &captureTestStream{Reader: bytes.NewReader(data)}
	stream := WrapResponseStream(c, source)
	c.Status(202)
	c.Set("Content-Type", "application/json")
	c.Response().SetBodyStream(stream, len(data))
	capture.Prepare(c)
	// Snapshot data must remain valid after pooled headers are reused.
	c.Response().Header.SetStatusCode(500)
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
	if completed != 0 {
		t.Fatal("stream completed before downstream write result")
	}
	writeError := errors.New("downstream disconnected")
	closer := stream.(fasthttp.ReadCloserWithError)
	if err := closer.CloseWithError(writeError); err != nil {
		t.Fatal(err)
	}
	_ = closer.CloseWithError(nil)
	if source.closed != 1 || !errors.Is(source.err, writeError) || completed != 1 {
		t.Fatal("stream ownership, write error, or completion was lost")
	}
	if result.Status != 202 || result.Bytes != uint64(len(data)) || len(result.Body) != ResponsePreviewLimit || !result.BodyTruncated || result.Error != writeError.Error() {
		t.Fatalf("incorrect completed stream: %+v", result)
	}
}
