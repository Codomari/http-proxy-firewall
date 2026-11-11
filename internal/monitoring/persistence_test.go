package monitoring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
)

type memoryCounterStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	loadErr  error
	failKey  string
	maxBytes int
}

func (s *memoryCounterStore) Load(ctx context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, false, s.loadErr
	}
	data, found := s.data[key]
	return bytes.Clone(data), found, ctx.Err()
}

func (s *memoryCounterStore) Save(ctx context.Context, key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == s.failKey || s.loadErr != nil {
		return errors.New("store unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[key] = bytes.Clone(data)
	s.maxBytes = max(s.maxBytes, len(data))
	return nil
}

func populatePersistentCounters(r *Registry) {
	app := registryApp(r, func(c fiber.Ctx) error {
		AddBytesIn(c, 7)
		switch c.Path() {
		case "/cve":
			RecordCVERejection(c)
			return c.Status(403).SendString("blocked")
		case "/error":
			return c.Status(502).SendString("error")
		default:
			return c.SendString("ok")
		}
	})
	handler := app.Handler()
	for i := range 300 {
		handler(requestContext(fmt.Sprintf("host-%03d.example", i), "/cve"))
	}
	handler(requestContext("host-000.example", "/error"))
	handler(requestContext("host-000.example", "/ok"))
	// A hostname over the configured capacity still contributes to totals.
	handler(requestContext("untracked.example", "/cve"))
	early := fiber.New()
	early.Use(func(c fiber.Ctx) error {
		r.RecordIPFirewallRejection(c, normalizeTestHost)
		return c.Status(444).Send(nil)
	})
	early.Handler()(requestContext("host-000.example", "/"))
}

func TestCounterLifecycleRestoresAllCumulativeCountersAndResetsGauges(t *testing.T) {
	store := &memoryCounterStore{}
	r := testRegistry(300)
	r.ConfigurePersistence(store, true, "test", nil)
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	populatePersistentCounters(r)
	wantTotals, wantHosts := r.Totals(), r.Hosts()
	if wantTotals.CVERejected == 0 || wantTotals.IPFirewallRejected == 0 || wantTotals.Errors5xx == 0 || wantTotals.UntrackedRequests == 0 || wantHosts[0].BytesIn == 0 || wantHosts[0].BytesOut == 0 {
		t.Fatal("fixture did not exercise every cumulative counter")
	}
	// Transient work must never reappear as stuck requests after a restart.
	r.totals.inflight.Store(12)
	r.hosts[wantHosts[0].Hostname].inflight.Store(4)
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored := testRegistry(300)
	restored.ConfigurePersistence(store, true, "test", nil)
	if err := restored.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restored.Stop(context.Background())
	if !reflect.DeepEqual(restored.Totals(), wantTotals) || !reflect.DeepEqual(restored.Hosts(), wantHosts) || !restored.CounterPersistence().Restored || restored.CounterPersistence().LastSaved.IsZero() {
		t.Fatalf("restart lost counters: totals=%+v want=%+v status=%+v", restored.Totals(), wantTotals, restored.CounterPersistence())
	}
	if store.maxBytes > 1<<20 || len(store.data) != 3 {
		t.Fatal("snapshot exceeded storage entry limits or failed to chunk hosts")
	}
}

func TestPartialCounterSavePreservesPreviousCompleteSnapshot(t *testing.T) {
	store := &memoryCounterStore{}
	r := testRegistry(300)
	r.ConfigurePersistence(store, true, "test", nil)
	populatePersistentCounters(r)
	if err := r.writeCounters(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantTotals, wantHosts := r.Totals(), r.Hosts()
	oldManifest := bytes.Clone(store.data["test"])
	r.totals.requests.Add(10)
	store.failKey = counterChunkKey("test", 1, 1)
	if err := r.writeCounters(context.Background()); err == nil || !bytes.Equal(store.data["test"], oldManifest) {
		t.Fatal("partial save replaced the published snapshot")
	}
	restored := testRegistry(300)
	restored.ConfigurePersistence(store, true, "test", nil)
	if err := restored.restoreCounters(context.Background()); err != nil || !reflect.DeepEqual(restored.Totals(), wantTotals) || !reflect.DeepEqual(restored.Hosts(), wantHosts) {
		t.Fatal("partial update damaged previous counters", err)
	}
	store.failKey = ""
	for range 4 {
		if err := r.writeCounters(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.data) != 5 {
		t.Fatal("repeated snapshots grew beyond two reusable banks")
	}
}

func TestCounterStartupFallbackAndCapacity(t *testing.T) {
	for _, failure := range []string{"offline", "missing", "malformed", "incomplete", "mismatched chunk"} {
		t.Run(failure, func(t *testing.T) {
			store := &memoryCounterStore{}
			source := testRegistry(300)
			source.ConfigurePersistence(store, true, "test", nil)
			populatePersistentCounters(source)
			if err := source.writeCounters(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "offline":
				store.loadErr = errors.New("offline")
			case "missing":
				store.data = nil
			case "malformed":
				store.data["test"] = []byte(`{"version":-1}`)
			case "incomplete":
				delete(store.data, counterChunkKey("test", 0, 1))
			case "mismatched chunk":
				store.data[counterChunkKey("test", 0, 1)] = []byte(`{"id":"wrong","hosts":[]}`)
			}
			r := testRegistry(300)
			r.ConfigurePersistence(store, true, "test", nil)
			if err := r.Start(context.Background()); err != nil {
				t.Fatal("optional Redis prevented startup", err)
			}
			defer r.Stop(context.Background())
			if r.Totals().Requests != 0 || len(r.Hosts()) != 0 || r.CounterPersistence().Restored {
				t.Fatal("startup restored partial/invalid data instead of starting from zero")
			}
		})
	}
	store := &memoryCounterStore{}
	source := testRegistry(300)
	source.ConfigurePersistence(store, true, "test", nil)
	populatePersistentCounters(source)
	if err := source.writeCounters(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := testRegistry(2)
	r.ConfigurePersistence(store, true, "test", nil)
	if err := r.restoreCounters(context.Background()); err != nil || len(r.Hosts()) != 2 || r.Totals().Requests != source.Totals().Requests {
		t.Fatal("restore did not respect current host capacity or preserve global totals", err)
	}
	store.loadErr = errors.New("offline")
	before := r.Totals()
	r.saveCounters(context.Background())
	if r.Totals() != before || !strings.Contains(r.CounterPersistence().Error, "memory") {
		t.Fatal("Redis failure changed live counters or was not reported")
	}
}
