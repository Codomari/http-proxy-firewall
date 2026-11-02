package monitoring

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"http-proxy-firewall/internal/config"
)

func testRegistry(capacity int) *Registry {
	return New(config.Config{Admin: config.Admin{Enabled: true, MaxHosts: capacity}})
}

func normalizeTestHost(host string) (string, error) {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(strings.TrimSuffix(host, ".")), nil
}

func requestContext(host, path string) *fasthttp.RequestCtx {
	ctx := new(fasthttp.RequestCtx)
	ctx.Init(new(fasthttp.Request), &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, nil)
	ctx.Request.Header.SetHost(host)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI(path)
	return ctx
}

func registryApp(r *Registry, handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use(r.Middleware(normalizeTestHost))
	app.Use(handler)
	return app
}

func TestPerHostCountersKeepWWWSeparate(t *testing.T) {
	r := testRegistry(8)
	app := registryApp(r, func(c fiber.Ctx) error {
		AddBytesIn(c, 3)
		switch c.Path() {
		case "/reject":
			return c.Status(403).SendString("no")
		case "/error":
			return c.Status(503).SendString("down")
		default:
			return c.SendString("ok")
		}
	})
	handler := app.Handler()
	for _, request := range []struct{ host, path string }{
		{"WWW.Example.Test:443", "/"}, {"example.test", "/reject"}, {"example.test.", "/error"},
	} {
		handler(requestContext(request.host, request.path))
	}
	totals := r.Totals()
	if totals.Requests != 3 || totals.InFlight != 0 || totals.Rejected != 1 || totals.Errors5xx != 1 || totals.TrackedHosts != 2 || totals.UntrackedRequests != 0 {
		t.Fatalf("incorrect totals: %+v", totals)
	}
	hosts := r.Hosts()
	if len(hosts) != 2 || hosts[0].Hostname != "example.test" || hosts[0].Requests != 2 || hosts[0].BytesIn != 6 || hosts[0].BytesOut != 6 || hosts[0].Rejected != 1 || hosts[0].Errors5xx != 1 || hosts[0].LastSeen.IsZero() {
		t.Fatalf("incorrect host snapshot: %+v", hosts)
	}
	if hosts[1].Hostname != "www.example.test" || hosts[1].BytesOut != 2 {
		t.Fatalf("www was grouped or bytes changed: %+v", hosts[1])
	}
}

func TestCapacityAndInvalidHostAreAggregatedWithoutNewState(t *testing.T) {
	r := testRegistry(2)
	app := registryApp(r, func(c fiber.Ctx) error { return c.SendStatus(200) })
	handler := app.Handler()
	for i := 0; i < 1000; i++ {
		handler(requestContext(fmt.Sprintf("host%d.example", i), "/"))
	}
	handler(requestContext(strings.Repeat("a", 254), "/"))
	totals := r.Totals()
	if totals.Requests != 1001 || totals.TrackedHosts != 2 || totals.UntrackedRequests != 999 || totals.InFlight != 0 || len(r.Hosts()) != 2 {
		t.Fatalf("capacity did not bound state: %+v", totals)
	}
	// A known host continues to update after capacity is reached.
	handler(requestContext("host0.example", "/"))
	if hosts := r.Hosts(); hosts[0].Hostname != "host0.example" || hosts[0].Requests != 2 {
		t.Fatalf("existing host stopped tracking: %+v", hosts)
	}
}

type errorAwareReader struct {
	io.Reader
	closes      atomic.Int64
	plainCloses atomic.Int64
	writeError  error
}

func (r *errorAwareReader) Close() error { r.plainCloses.Add(1); return nil }
func (r *errorAwareReader) CloseWithError(err error) error {
	r.closes.Add(1)
	r.writeError = err
	return nil
}

func TestResponseStreamLifetimeCloseErrorAndContextReuse(t *testing.T) {
	r := testRegistry(8)
	source := &errorAwareReader{Reader: strings.NewReader("payload")}
	app := registryApp(r, func(c fiber.Ctx) error {
		c.Response().SetBodyStream(WrapStream(c, source, 200), 7)
		return nil
	})
	handler := app.Handler()
	ctx := requestContext("first.example", "/")
	handler(ctx)
	if totals := r.Totals(); totals.Requests != 1 || totals.InFlight != 1 {
		t.Fatalf("stream completed at headers: %+v", totals)
	}
	stream := ctx.Response.BodyStream()
	if _, ok := stream.(io.Closer); ok {
		t.Fatal("wrapper implements Close and would lose write errors")
	}
	// The completion handle must own host state independently of request bytes.
	ctx.Request.Header.SetHost("reused.example")
	var small [3]byte
	if n, err := stream.Read(small[:]); n != 3 || err != nil {
		t.Fatalf("partial read: %d %v", n, err)
	}
	if r.Totals().InFlight != 1 {
		t.Fatal("partial read completed transfer")
	}
	failure := errors.New("downstream disconnected")
	closer := stream.(fasthttp.ReadCloserWithError)
	if err := closer.CloseWithError(failure); err != nil {
		t.Fatal(err)
	}
	if err := closer.CloseWithError(nil); err != nil {
		t.Fatal(err)
	}
	if source.closes.Load() != 1 || source.plainCloses.Load() != 0 || source.writeError != failure {
		t.Fatal("underlying error-aware closer was not preserved exactly once")
	}
	hosts := r.Hosts()
	if totals := r.Totals(); totals.InFlight != 0 || len(hosts) != 1 || hosts[0].Hostname != "first.example" || hosts[0].BytesOut != 3 {
		t.Fatalf("incorrect stream completion: totals=%+v hosts=%+v", totals, hosts)
	}
}

func TestEOFDoesNotCompleteUntilStreamClose(t *testing.T) {
	r := testRegistry(8)
	app := registryApp(r, func(c fiber.Ctx) error {
		c.Response().SetBodyStream(WrapStream(c, strings.NewReader("x"), 200), 1)
		return nil
	})
	ctx := requestContext("example.test", "/")
	app.Handler()(ctx)
	if _, err := io.ReadAll(ctx.Response.BodyStream()); err != nil {
		t.Fatal(err)
	}
	if r.Totals().InFlight != 1 {
		t.Fatal("EOF released transfer before close")
	}
	if err := ctx.Response.CloseBodyStream(); err != nil {
		t.Fatal(err)
	}
	if r.Totals().InFlight != 0 || r.Hosts()[0].BytesOut != 1 {
		t.Fatal("stream close failed to release completion")
	}
}

func TestManualTunnelCompletionOwnsCountersAndIsIdempotent(t *testing.T) {
	r := testRegistry(8)
	var finish func(int, uint64)
	app := registryApp(r, func(c fiber.Ctx) error { finish = Completion(c); return c.SendStatus(101) })
	ctx := requestContext("tunnel.example", "/")
	app.Handler()(ctx)
	if r.Totals().InFlight != 1 {
		t.Fatal("upgrade completed at handler return")
	}
	ctx.Request.Reset()
	ctx.Request.Header.SetHost("reused.example")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); finish(101, 123) }()
	}
	wg.Wait()
	hosts := r.Hosts()
	if r.Totals().InFlight != 0 || len(hosts) != 1 || hosts[0].Hostname != "tunnel.example" || hosts[0].BytesOut != 123 {
		t.Fatalf("bad manual completion: %+v", hosts)
	}
}

func TestConcurrentHostRequestsAndSnapshots(t *testing.T) {
	r := testRegistry(8)
	app := registryApp(r, func(c fiber.Ctx) error {
		AddBytesIn(c, 2)
		RecordCVERejection(c)
		RecordCVERejection(c)
		return c.SendString("x")
	})
	handler := app.Handler()
	const workers, perWorker = 16, 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				handler(requestContext("hot.example", "/"))
				_ = r.Hosts()
				_ = r.Totals()
			}
		}()
	}
	wg.Wait()
	totals := r.Totals()
	hosts := r.Hosts()
	if totals.Requests != workers*perWorker || totals.InFlight != 0 || len(hosts) != 1 || hosts[0].Requests != workers*perWorker || hosts[0].BytesIn != 2*workers*perWorker || hosts[0].BytesOut != workers*perWorker || totals.CVERejected != workers*perWorker || hosts[0].CVERejected != workers*perWorker {
		t.Fatalf("lost concurrent updates: totals=%+v hosts=%+v", totals, hosts)
	}
}

func TestRegistryClonesRetainedHostString(t *testing.T) {
	r := testRegistry(8)
	data := []byte("original.example")
	view := unsafe.String(unsafe.SliceData(data), len(data))
	host := r.findHost(view)
	for i := range data {
		data[i] = 'x'
	}
	if host.hostname != "original.example" || r.findHost("original.example") != host {
		t.Fatal("registry retained borrowed request hostname")
	}
}

func TestDisabledRegistryDoesNotTrackAllocateOrStartWorkers(t *testing.T) {
	r := New(config.Config{})
	before := runtime.NumGoroutine()
	normalized := false
	app := fiber.New()
	app.Use(r.Middleware(func(host string) (string, error) { normalized = true; return host, nil }))
	reader := strings.NewReader("x")
	app.Use(func(c fiber.Ctx) error {
		if WrapStream(c, reader, 200) != reader {
			t.Fatal("disabled registry wrapped stream")
		}
		AddBytesIn(c, 10)
		RecordCVERejection(c)
		Completion(c)(200, 10)
		return c.SendString("ok")
	})
	app.Handler()(requestContext("example.test", "/"))
	if normalized || r.Totals().CVERejected != 0 || r.Totals().Requests != 0 || len(r.Hosts()) != 0 {
		t.Fatal("disabled registry tracked requests")
	}
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("monitoring started workers: before=%d after=%d", before, after)
	}
}

func TestRuntimeLabelsRepresentGoMemory(t *testing.T) {
	r := testRegistry(8)
	snapshot := r.Runtime()
	if snapshot.UptimeSeconds < 0 || snapshot.Goroutines < 1 || snapshot.CPUCount < 1 || snapshot.GOMAXPROCS < 1 || snapshot.SystemBytes < snapshot.HeapAllocatedBytes || snapshot.HeapInUseBytes < snapshot.HeapAllocatedBytes || snapshot.StackBytes == 0 {
		t.Fatalf("invalid runtime snapshot: %+v", snapshot)
	}
}

func TestErrorCompletionAndStreamCleanupDoNotDoubleCount(t *testing.T) {
	r := testRegistry(8)
	app := registryApp(r, func(c fiber.Ctx) error {
		c.Response().SetBodyStream(WrapStream(c, bytes.NewReader([]byte("never sent")), 200), 10)
		return fiber.ErrServiceUnavailable
	})
	ctx := requestContext("error.example", "/")
	app.Handler()(ctx)
	_ = ctx.Response.CloseBodyStream()
	if totals := r.Totals(); totals.Requests != 1 || totals.InFlight != 0 || totals.Errors5xx != 1 {
		t.Fatalf("error double-counted: %+v", totals)
	}
}
