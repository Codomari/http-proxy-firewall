package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSnapshotSaveIsSynchronousAndHasNoExpiry(t *testing.T) {
	r := New(enabledConfig(), nil)
	wrote := false
	r.newBackend = func() backend {
		return &fakeBackend{setFn: func(ctx context.Context, key string, value []byte, ttl time.Duration) error {
			if key != "counter-manifest" || string(value) != "snapshot" || ttl != 0 {
				t.Error("invalid durable snapshot write", key, string(value), ttl)
			}
			wrote = true
			return nil
		}}
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRemote(t, r)
	if err := r.Save(context.Background(), "counter-manifest", []byte("snapshot")); err != nil || !wrote || r.retained.Load() != 0 {
		t.Fatal("Save returned before completion or leaked bytes", err)
	}
}

func TestSnapshotReadsDistinguishUnavailableFromMissing(t *testing.T) {
	r := New(enabledConfig(), nil)
	if _, _, err := r.Load(context.Background(), "counter-manifest"); err == nil {
		t.Fatal("unstarted Redis looked like a missing snapshot")
	}
	r.newBackend = func() backend { return &fakeBackend{} }
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRemote(t, r)
	r.unavailableUntil.Store(time.Now().Add(time.Second).UnixNano())
	if _, _, err := r.Load(context.Background(), "counter-manifest"); err == nil {
		t.Fatal("unavailable Redis looked like a missing snapshot")
	}
	if err := r.Save(context.Background(), "counter-manifest", nil); err == nil {
		t.Fatal("unavailable Redis reported a successful save")
	}
	r.unavailableUntil.Store(0)
	r.client = &fakeBackend{setFn: func(context.Context, string, []byte, time.Duration) error { return errors.New("write failed") }}
	if err := r.Save(context.Background(), "counter-manifest", nil); err == nil {
		t.Fatal("Redis write failure was hidden")
	}
}
