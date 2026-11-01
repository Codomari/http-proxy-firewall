package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"http-proxy-firewall/internal/config"
)

type fakeBackend struct {
	getFn  func(context.Context, string) ([]byte, error)
	setFn  func(context.Context, string, []byte, time.Duration) error
	closed atomic.Int32
}

func (b *fakeBackend) get(ctx context.Context, key string) ([]byte, error) {
	if b.getFn == nil {
		return nil, nil
	}
	return b.getFn(ctx, key)
}
func (b *fakeBackend) set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if b.setFn == nil {
		return nil
	}
	return b.setFn(ctx, key, value, ttl)
}
func (b *fakeBackend) close() error { b.closed.Add(1); return nil }

func enabledConfig() config.Config {
	return config.Config{Redis: config.Redis{Enabled: true, QueueSize: 1, Workers: 1, Timeout: time.Second}}
}

func stopRemote(t *testing.T, remote *Remote) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := remote.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledAndUnstartedStorageHaveNoBackendEffects(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := enabledConfig()
		cfg.Redis.Enabled = enabled
		r := New(cfg, nil)
		var constructed atomic.Int32
		r.newBackend = func() backend { constructed.Add(1); return &fakeBackend{} }
		if r.Set("key", []byte("value"), time.Hour) {
			t.Fatal("accepted write before Start")
		}
		if _, ok, err := r.Get(context.Background(), "key"); err != nil || ok {
			t.Fatal("read before Start")
		}
		if constructed.Load() != 0 {
			t.Fatal("constructed backend before Start")
		}
		if !enabled {
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if constructed.Load() != 0 || r.Set("key", nil, time.Hour) {
				t.Fatal("disabled backend was activated")
			}
		}
		stopRemote(t, r)
		stopRemote(t, r)
	}
}

func TestWritesOwnBorrowedBytesAndQueueIsBounded(t *testing.T) {
	r := New(enabledConfig(), nil)
	entered := make(chan write, 3)
	b := &fakeBackend{setFn: func(ctx context.Context, key string, value []byte, ttl time.Duration) error {
		entered <- write{key: key, value: value, ttl: ttl}
		<-ctx.Done()
		return ctx.Err()
	}}
	r.newBackend = func() backend { return b }
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	keyBytes := []byte("COOKIES:original")
	key := unsafe.String(unsafe.SliceData(keyBytes), len(keyBytes))
	value := []byte("original")
	if !r.Set(key, value, time.Hour) {
		t.Fatal("first write rejected")
	}
	first := <-entered
	keyBytes[0], value[0] = 'x', 'x'
	if first.key != "COOKIES:original" || string(first.value) != "original" || first.ttl != time.Hour {
		t.Fatalf("borrowed buffers retained: key=%q, value=%q", first.key, first.value)
	}
	if !r.Set("second", nil, time.Hour) {
		t.Fatal("queue rejected available slot")
	}
	if r.Set("third", nil, time.Hour) {
		t.Fatal("full queue accepted write")
	}
	stopRemote(t, r)
	if r.retained.Load() != 0 || b.closed.Load() != 1 {
		t.Fatal("shutdown leaked retained writes or backend")
	}
	if r.Set("late", nil, time.Hour) {
		t.Fatal("accepted write after Stop")
	}
}

func TestReadDeadlineOpensCircuitAndAllowsOneProbe(t *testing.T) {
	cfg := enabledConfig()
	cfg.Redis.Timeout = 20 * time.Millisecond
	r := New(cfg, nil)
	var reads atomic.Int32
	b := &fakeBackend{getFn: func(ctx context.Context, key string) ([]byte, error) {
		reads.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r.newBackend = func() backend { return b }
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stopRemote(t, r)
	if _, _, err := r.Get(context.Background(), "one"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error: %v", err)
	}
	if _, ok, err := r.Get(context.Background(), "two"); err != nil || ok {
		t.Fatalf("circuit fallback: %v", err)
	}
	if reads.Load() != 1 {
		t.Fatal("open circuit attempted another read")
	}
	if r.Set("key", []byte("value"), time.Hour) {
		t.Fatal("open circuit accepted persistence")
	}
	// Expire the retry delay without sleeping. Only one request may probe.
	r.unavailableUntil.Store(time.Now().Add(-time.Second).UnixNano())
	allowed, probing := r.begin()
	if !allowed || !probing {
		t.Fatal("circuit did not allow probe")
	}
	if allowed, _ := r.begin(); allowed {
		t.Fatal("parallel recovery probe allowed")
	}
	r.probe.Store(false)
}

func TestStopCancelsConcurrentRequestsAndWriters(t *testing.T) {
	cfg := enabledConfig()
	cfg.Redis.QueueSize = 8
	r := New(cfg, nil)
	entered := make(chan struct{}, 32)
	b := &fakeBackend{getFn: func(ctx context.Context, key string) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r.newBackend = func() backend { return b }
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Get(context.Background(), "read")
			for i := 0; i < 100; i++ {
				r.Set("write", []byte("value"), time.Hour)
			}
		}()
	}
	<-entered
	stopRemote(t, r)
	wg.Wait()
	if b.closed.Load() != 1 || r.retained.Load() != 0 {
		t.Fatal("shutdown did not finish cleanup")
	}
}

func TestPersistenceByteBudget(t *testing.T) {
	cfg := enabledConfig()
	cfg.Redis.QueueSize = 64
	r := New(cfg, nil)
	entered := make(chan struct{}, 1)
	b := &fakeBackend{setFn: func(ctx context.Context, key string, value []byte, ttl time.Duration) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	r.newBackend = func() backend { return b }
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxValueBytes)
	if !r.Set("first", data, time.Hour) {
		t.Fatal("first write rejected")
	}
	<-entered
	accepted := 1
	for r.Set("queued", data, time.Hour) {
		accepted++
	}
	if accepted > maxRetainedBytes/maxValueBytes || r.retained.Load() > maxRetainedBytes {
		t.Fatal("persistence byte budget exceeded")
	}
	if r.Set("oversized", make([]byte, maxValueBytes+1), time.Hour) {
		t.Fatal("oversized value accepted")
	}
	stopRemote(t, r)
}
