// Package storage provides optional Redis with bounded asynchronous persistence.
package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"http-proxy-firewall/internal/config"
)

const (
	maxKeyBytes      = 1024
	maxValueBytes    = 1 << 20
	maxRetainedBytes = 16 << 20
	retryDelay       = time.Second
)

type backend interface {
	get(context.Context, string) ([]byte, error)
	set(context.Context, string, []byte, time.Duration) error
	close() error
}

type redisBackend struct{ client *redis.Client }

func (r *redisBackend) get(ctx context.Context, key string) ([]byte, error) {
	// Check length atomically before returning bytes, so an oversized value
	// already in Redis cannot force an unbounded allocation in this process.
	const script = `if redis.call('EXISTS', KEYS[1]) == 0 then return false end
if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then return redis.error_reply('value exceeds size limit') end
return redis.call('GET', KEYS[1])`
	value, err := r.client.Eval(ctx, script, []string{key}, maxValueBytes).Text()
	return []byte(value), err
}
func (r *redisBackend) set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, data, ttl).Err()
}
func (r *redisBackend) close() error { return r.client.Close() }

type write struct {
	key      string
	value    []byte
	ttl      time.Duration
	retained int64
}

// Remote owns one Redis client. Constructors perform no network/background work.
// Writes may be dropped when unavailable or full: local state remains authoritative.
type Remote struct {
	cfg              config.Redis
	logger           *slog.Logger
	mx               sync.Mutex
	started          bool
	stopped          bool
	closing          bool
	client           backend
	newBackend       func() backend
	queue            chan write
	runCtx           context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	wg               sync.WaitGroup
	retained         atomic.Int64
	unavailableUntil atomic.Int64
	probe            atomic.Bool
	reads            atomic.Uint64
	writes           atomic.Uint64
	readErrors       atomic.Uint64
	writeErrors      atomic.Uint64
	lastSuccess      atomic.Int64
}

func New(cfg config.Config, logger *slog.Logger) *Remote {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	settings := cfg.Redis
	if settings.Timeout <= 0 {
		settings.Timeout = 200 * time.Millisecond
	}
	if settings.QueueSize <= 0 {
		settings.QueueSize = 256
	}
	if settings.QueueSize > 65536 {
		settings.QueueSize = 65536
	}
	if settings.Workers <= 0 {
		settings.Workers = 2
	}
	if settings.Workers > 64 {
		settings.Workers = 64
	}
	if settings.Address == "" {
		settings.Address = "127.0.0.1:6379"
	}
	r := &Remote{cfg: settings, logger: logger}
	r.newBackend = func() backend {
		poolSize := settings.Workers + 8
		return &redisBackend{client: redis.NewClient(&redis.Options{
			Addr: settings.Address, Password: settings.Password, DB: settings.DB,
			PoolSize: poolSize, MaxActiveConns: poolSize,
			PoolTimeout: settings.Timeout, DialTimeout: settings.Timeout,
			ReadTimeout: settings.Timeout, WriteTimeout: settings.Timeout,
			ContextTimeoutEnabled: true, MaxRetries: -1,
			ConnMaxIdleTime: time.Minute,
		})}
	}
	return r
}

// Start never requires Redis to be reachable. Redis connections are lazy.
func (r *Remote) Start(ctx context.Context) error {
	r.mx.Lock()
	defer r.mx.Unlock()
	if r.stopped {
		return errors.New("remote storage already stopped")
	}
	if r.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.started, r.done = true, make(chan struct{})
	if !r.cfg.Enabled {
		close(r.done)
		return nil
	}
	r.client = r.newBackend()
	r.queue = make(chan write, r.cfg.QueueSize)
	r.runCtx, r.cancel = context.WithCancel(context.Background())
	for i := 0; i < r.cfg.Workers; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	return nil
}

func (r *Remote) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if len(key) == 0 || len(key) > maxKeyBytes {
		return nil, false, nil
	}
	r.mx.Lock()
	if !r.started || r.stopped || !r.cfg.Enabled {
		r.mx.Unlock()
		return nil, false, nil
	}
	client, runCtx := r.client, r.runCtx
	r.wg.Add(1)
	r.mx.Unlock()
	defer r.wg.Done()
	allowed, probing := r.begin()
	if !allowed {
		return nil, false, nil
	}
	if probing {
		defer r.probe.Store(false)
	}
	operationCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	stop := context.AfterFunc(runCtx, cancel)
	defer cancel()
	defer stop()
	r.reads.Add(1)
	value, err := client.get(operationCtx, key)
	if errors.Is(err, redis.Nil) {
		r.succeeded()
		return nil, false, nil
	}
	if err != nil {
		r.readErrors.Add(1)
		// Client cancellation does not indicate that Redis is unhealthy.
		if ctx.Err() == nil && runCtx.Err() == nil {
			r.failed()
		}
		return nil, false, err
	}
	r.succeeded()
	if len(value) > maxValueBytes {
		return nil, false, errors.New("remote value exceeds size limit")
	}
	return value, true, nil
}

// Set copies key and value before retaining them. Both entry count and total
// queued/in-flight bytes are bounded. It never blocks on Redis or a full queue.
func (r *Remote) Set(key string, value []byte, ttl time.Duration) bool {
	if len(key) == 0 || len(key) > maxKeyBytes || len(value) > maxValueBytes || ttl <= 0 {
		return false
	}
	r.mx.Lock()
	defer r.mx.Unlock()
	if !r.started || r.stopped || !r.cfg.Enabled || time.Now().UnixNano() < r.unavailableUntil.Load() || len(r.queue) == cap(r.queue) {
		return false
	}
	retained := int64(len(key) + len(value))
	if r.retained.Add(retained) > maxRetainedBytes {
		r.retained.Add(-retained)
		return false
	}
	entry := write{key: strings.Clone(key), value: bytes.Clone(value), ttl: ttl, retained: retained}
	select {
	case r.queue <- entry:
		return true
	default:
		r.retained.Add(-retained)
		return false
	}
}

func (r *Remote) worker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.runCtx.Done():
			return
		case entry := <-r.queue:
			r.persist(entry)
		}
	}
}

func (r *Remote) persist(entry write) {
	defer r.retained.Add(-entry.retained)
	allowed, probing := r.begin()
	if !allowed {
		return
	}
	if probing {
		defer r.probe.Store(false)
	}
	ctx, cancel := context.WithTimeout(r.runCtx, r.cfg.Timeout)
	r.writes.Add(1)
	err := r.client.set(ctx, entry.key, entry.value, entry.ttl)
	cancel()
	if err != nil {
		r.writeErrors.Add(1)
		if r.runCtx.Err() == nil {
			r.failed()
		}
	} else {
		r.succeeded()
	}
}

func (r *Remote) begin() (allowed, probing bool) {
	until := r.unavailableUntil.Load()
	if until == 0 {
		return true, false
	}
	if time.Now().UnixNano() < until {
		return false, false
	}
	return r.probe.CompareAndSwap(false, true), true
}

func (r *Remote) succeeded() {
	r.lastSuccess.Store(time.Now().UnixNano())
	r.unavailableUntil.Store(0)
}

func (r *Remote) failed() {
	now := time.Now()
	previous := r.unavailableUntil.Swap(now.Add(retryDelay).UnixNano())
	if previous <= now.UnixNano() {
		r.logger.Warn("optional Redis unavailable; using local state temporarily")
	}
}

// Stop cancels outstanding operations and discards pending optional writes.
// Cleanup continues if the caller's deadline expires, and Stop may be retried.
func (r *Remote) Stop(ctx context.Context) error {
	r.mx.Lock()
	r.stopped = true
	if !r.started {
		r.mx.Unlock()
		return nil
	}
	done := r.done
	if r.cfg.Enabled && !r.closing {
		r.closing = true
		r.cancel()
		go func() {
			r.wg.Wait()
			for {
				select {
				case entry := <-r.queue:
					r.retained.Add(-entry.retained)
				default:
					_ = r.client.close()
					close(done)
					return
				}
			}
		}()
	}
	r.mx.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
