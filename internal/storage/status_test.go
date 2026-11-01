package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisTelemetryCountsBackendOperationsAndCircuitFallback(t *testing.T) {
	r := New(enabledConfig(), nil)
	r.newBackend = func() backend {
		return &fakeBackend{getFn: func(_ context.Context, key string) ([]byte, error) {
			switch key {
			case "missing":
				return nil, redis.Nil
			case "failed":
				return nil, errors.New("unavailable")
			default:
				return []byte("value"), nil
			}
		}}
	}
	if r.Snapshot().Status != "not_started" {
		t.Fatal("unexpected initial status")
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRemote(t, r)
	for range 3 {
		if s := r.Snapshot(); s.Status != "not_checked" || s.Reads != 0 || s.Writes != 0 {
			t.Fatal("dashboard observation queried Redis")
		}
	}
	_, _, _ = r.Get(context.Background(), "present")
	_, _, _ = r.Get(context.Background(), "missing")
	r.persist(write{key: "write", value: []byte("value"), ttl: time.Hour})
	s := r.Snapshot()
	if s.Status != "available" || s.Reads != 2 || s.Writes != 1 || s.ReadErrors != 0 || s.LastSuccess == nil {
		t.Fatalf("wrong successful counters: %+v", s)
	}
	_, _, _ = r.Get(context.Background(), "failed")
	_, _, _ = r.Get(context.Background(), "skipped during backoff")
	r.persist(write{key: "skipped", ttl: time.Hour})
	s = r.Snapshot()
	if s.Status != "unavailable" || s.Reads != 3 || s.ReadErrors != 1 || s.Writes != 1 {
		t.Fatalf("circuit fallback counted as a query: %+v", s)
	}
}

func TestRedisWriteFailureAndDisabledTelemetry(t *testing.T) {
	disabled := New(enabledConfig(), nil)
	disabled.cfg.Enabled = false
	if s := disabled.Snapshot(); s.Enabled || s.Status != "disabled" || s.Reads != 0 || s.Writes != 0 {
		t.Fatal("disabled status incorrect")
	}
	r := New(enabledConfig(), nil)
	r.newBackend = func() backend {
		return &fakeBackend{setFn: func(context.Context, string, []byte, time.Duration) error { return errors.New("failed") }}
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRemote(t, r)
	r.persist(write{key: "write", ttl: time.Hour})
	if s := r.Snapshot(); s.Status != "unavailable" || s.Writes != 1 || s.WriteErrors != 1 {
		t.Fatalf("write failure not recorded: %+v", s)
	}
}
