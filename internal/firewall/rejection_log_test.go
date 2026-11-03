package firewall

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	cve2026109618 "http-proxy-firewall/internal/firewall/cves/2026-109618"
	cve2026109619 "http-proxy-firewall/internal/firewall/cves/2026-109619"
)

func TestRejectionSamplerFirstEventReasonIsolationAndExpiry(t *testing.T) {
	sampler := rejectionSampler{interval: time.Second}
	now := time.Unix(1700000000, 0)
	for reason := rejectionReason(0); reason < rejectionReasonCount; reason++ {
		if emit, suppressed := sampler.allow(reason, now); !emit || suppressed != 0 {
			t.Fatalf("first %s rejection was not emitted", rejectionReasonNames[reason])
		}
		for i := 0; i < 3; i++ {
			if emit, _ := sampler.allow(reason, now.Add(time.Duration(i)*time.Millisecond)); emit {
				t.Fatal("repeated rejection was not sampled")
			}
		}
		if emit, suppressed := sampler.allow(reason, now.Add(time.Second)); !emit || suppressed != 3 {
			t.Fatalf("next %s sample: emit=%t suppressed=%d", rejectionReasonNames[reason], emit, suppressed)
		}
		if emit, suppressed := sampler.allow(reason, now.Add(2*time.Second)); !emit || suppressed != 0 {
			t.Fatal("suppression count was not reset")
		}
	}
}

func TestZeroRejectionIntervalPreservesFullAudit(t *testing.T) {
	sampler := rejectionSampler{}
	now := time.Now()
	for i := 0; i < 100; i++ {
		if emit, suppressed := sampler.allow(rejectionMalformed, now); !emit || suppressed != 0 {
			t.Fatal("zero interval sampled a rejection")
		}
	}
}

func TestRejectionSamplerConcurrentAccounting(t *testing.T) {
	sampler := rejectionSampler{interval: time.Second}
	now := time.Unix(1700000000, 0)
	var emitted, reported atomic.Uint64
	var wg sync.WaitGroup
	const workers, perWorker = 32, 1000
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				if emit, suppressed := sampler.allow(rejectionMalformed, now); emit {
					emitted.Add(1)
					reported.Add(suppressed)
				}
			}
		}()
	}
	wg.Wait()
	if emitted.Load() != 1 {
		t.Fatalf("concurrent samples emitted %d logs", emitted.Load())
	}
	emit, remaining := sampler.allow(rejectionMalformed, now.Add(time.Second))
	if !emit || emitted.Load()+reported.Load()+remaining != workers*perWorker {
		t.Fatalf("lost rejection accounting: emitted=%d reported=%d remaining=%d", emitted.Load(), reported.Load(), remaining)
	}
}

type countedMalformedError struct{ formatted atomic.Int64 }

func (e *countedMalformedError) Error() string { e.formatted.Add(1); return "malformed request" }
func (*countedMalformedError) Unwrap() error   { return cve2026109618.ErrMalformed }

func TestRejectionLoggingSamplesBeforeFormattingAndKeepsResponseStatus(t *testing.T) {
	var output bytes.Buffer
	cfg := testConfig()
	cfg.Firewall.RejectionLogInterval = time.Second
	e := testEngine(t, cfg, nil)
	e.logger = slog.New(slog.NewTextHandler(&output, nil))
	now := time.Unix(1700000000, 0)
	e.now = func() time.Time { return now }
	app := fiber.New()
	ctx := new(fasthttp.RequestCtx)
	ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP("198.51.100.9")}, nil)
	ctx.Request.Header.SetHost("WWW.Example.Test:443")
	c := app.AcquireCtx(ctx)
	defer app.ReleaseCtx(c)
	c.Locals(clientIPKey{}, "198.51.100.9")
	malformed := new(countedMalformedError)
	body := bytes.Repeat([]byte("\\\"\r\n\x00\xff"), 300)
	if err := e.reject(c, 400, malformed, body); err != nil {
		t.Fatal(err)
	}
	formatted := malformed.formatted.Load()
	if formatted == 0 {
		t.Fatal("first rejection was not formatted")
	}
	for i := 0; i < 3; i++ {
		if err := e.reject(c, 400, malformed, body); err != nil {
			t.Fatal(err)
		}
		if ctx.Response.StatusCode() != 400 {
			t.Fatal("sampling changed rejection response")
		}
	}
	if malformed.formatted.Load() != formatted || strings.Count(output.String(), "\n") != 1 {
		t.Fatal("suppressed rejection performed logging work")
	}
	now = now.Add(time.Second)
	if err := e.reject(c, 400, malformed, body); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "suppressed=3") || !strings.Contains(lines[1], "client_ip=198.51.100.9") || !strings.Contains(lines[1], "reason=malformed") || !strings.Contains(lines[1], "form_data=") || !strings.Contains(lines[1], "hostname=www.example.test") {
		t.Fatalf("sample lost required context: %q", output.String())
	}
	if err := e.reject(c, 415, errors.New("unsupported encoding"), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "\n") != 3 {
		t.Fatal("one reason's traffic suppressed another reason's first sample")
	}
}

func TestRejectionHostnameOmittedWhenUnavailable(t *testing.T) {
	for _, host := range []string{"", "bad\nhost"} {
		var output bytes.Buffer
		e := testEngine(t, testConfig(), nil)
		e.logger = slog.New(slog.NewTextHandler(&output, nil))
		app := fiber.New()
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetHost(host)
		c := app.AcquireCtx(&ctx)
		if err := e.reject(c, 400, errors.New("failed to read complete request body"), nil); err != nil {
			t.Fatal(err)
		}
		app.ReleaseCtx(c)
		if strings.Contains(output.String(), "hostname=") {
			t.Fatal("rejection logged an invalid or unavailable hostname")
		}
	}
}

func TestDisabledRejectionLoggingSkipsFormattingAndSampling(t *testing.T) {
	var output bytes.Buffer
	cfg := testConfig()
	cfg.Firewall.RejectionLogInterval = time.Second
	e := testEngine(t, cfg, nil)
	e.logger = slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelError}))
	app := fiber.New()
	ctx := new(fasthttp.RequestCtx)
	ctx.Init(new(fasthttp.Request), nil, nil)
	c := app.AcquireCtx(ctx)
	defer app.ReleaseCtx(c)
	malformed := new(countedMalformedError)
	if err := e.reject(c, 400, malformed, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 || malformed.formatted.Load() != 0 || e.rejectionLogs.buckets[rejectionMalformed].next.Load() != 0 {
		t.Fatal("disabled logger performed formatting/sampling work")
	}
}

func TestRejectionReasonClassificationIsFixed(t *testing.T) {
	for _, tt := range []struct {
		status int
		err    error
		want   rejectionReason
	}{
		{400, cve2026109618.ErrMalformed, rejectionMalformed},
		{413, cve2026109618.ErrBodyTooLarge, rejectionBodyLimit},
		{413, cve2026109618.ErrInputLimit, rejectionInputLimit},
		{403, cve2026109619.ErrUploadProgress, rejectionUploadProgress},
		{415, errors.New("arbitrary client text"), rejectionEncoding},
		{503, errors.New("arbitrary client text"), rejectionOverload},
		{400, errors.New("arbitrary client text"), rejectionBodyPolicy},
		{500, errors.New("arbitrary client text"), rejectionOther},
	} {
		if got := reasonForRejection(tt.status, tt.err); got != tt.want {
			t.Errorf("status %d got reason %d want %d", tt.status, got, tt.want)
		}
	}
}
