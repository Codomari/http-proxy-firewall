package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

const counterSaveInterval = 5 * time.Second
const counterOperationTimeout = 3 * time.Second
const hostsPerCounterChunk = 256
const maxPersistedHosts = 1_000_000

type CounterStore interface {
	Load(context.Context, string) ([]byte, bool, error)
	Save(context.Context, string, []byte) error
}

type CounterPersistenceSnapshot struct {
	Enabled   bool      `json:"enabled"`
	Restored  bool      `json:"restored"`
	LastSaved time.Time `json:"last_saved"`
	Error     string    `json:"error"`
}

type counterPersistence struct {
	store     CounterStore
	key       string
	logger    *slog.Logger
	lifeMu    sync.Mutex
	started   bool
	stopped   bool
	finalized bool
	cancel    context.CancelFunc
	done      chan struct{}
	statusMu  sync.Mutex
	status    CounterPersistenceSnapshot
}

type counterManifest struct {
	Version   int            `json:"version"`
	ID        string         `json:"id"`
	Bank      int            `json:"bank"`
	Chunks    int            `json:"chunks"`
	HostCount int            `json:"host_count"`
	SavedAt   time.Time      `json:"saved_at"`
	Totals    TotalsSnapshot `json:"totals"`
}

type counterChunk struct {
	ID    string         `json:"id"`
	Hosts []HostSnapshot `json:"hosts"`
}

// ConfigurePersistence must be called before Start or request handling.
// Each app sharing a Redis database must use its own stable key.
func (r *Registry) ConfigurePersistence(store CounterStore, enabled bool, key string, logger *slog.Logger) {
	if key == "" {
		key = "MONITORING:COUNTERS:v1"
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	r.persistence.store, r.persistence.key, r.persistence.logger = store, key, logger
	r.persistence.status.Enabled = r.enabled && enabled && store != nil
}

func (r *Registry) CounterPersistence() CounterPersistenceSnapshot {
	p := &r.persistence
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	return p.status
}

// Start restores a complete snapshot before listeners open. Redis errors are
// optional: publish no partial data and continue from the initial zero state.
func (r *Registry) Start(ctx context.Context) error {
	p := &r.persistence
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()
	if p.stopped {
		return errors.New("monitoring already stopped")
	}
	if p.started || !p.status.Enabled {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	loadCtx, cancel := context.WithTimeout(ctx, counterOperationTimeout)
	err := r.restoreCounters(loadCtx)
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		p.setError("Redis counters could not be loaded; started from zero")
		p.logger.Warn("monitoring counters unavailable at startup; starting from zero", "error", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done, p.started = cancel, make(chan struct{}), true
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(counterSaveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				r.saveCounters(runCtx)
			}
		}
	}()
	return nil
}

// Stop runs after listeners and upstream transfers drain, but before Redis
// stops. The final save is synchronous; it cannot be discarded in Redis's queue.
func (r *Registry) Stop(ctx context.Context) error {
	p := &r.persistence
	p.lifeMu.Lock()
	p.stopped = true
	if !p.started {
		p.lifeMu.Unlock()
		return nil
	}
	p.cancel()
	done := p.done
	p.lifeMu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()
	if !p.finalized {
		r.saveCounters(ctx)
		p.finalized = true
	}
	return ctx.Err()
}

func (p *counterPersistence) setError(message string) {
	p.statusMu.Lock()
	p.status.Error = message
	p.statusMu.Unlock()
}

func decodeCounterManifest(data []byte) (counterManifest, error) {
	var manifest counterManifest
	if len(data) > 64<<10 || json.Unmarshal(data, &manifest) != nil || manifest.Version != 1 || manifest.ID == "" || len(manifest.ID) > 64 || manifest.Bank < 0 || manifest.Bank > 1 || manifest.HostCount < 0 || manifest.HostCount > maxPersistedHosts || manifest.Chunks != (manifest.HostCount+hostsPerCounterChunk-1)/hostsPerCounterChunk {
		return manifest, errors.New("invalid monitoring counter manifest")
	}
	return manifest, nil
}

func counterChunkKey(key string, bank, index int) string {
	return fmt.Sprintf("%s:%d:%d", key, bank, index)
}

func (r *Registry) restoreCounters(ctx context.Context) error {
	p := &r.persistence
	data, found, err := p.store.Load(ctx, p.key)
	if err != nil || !found {
		return err
	}
	manifest, err := decodeCounterManifest(data)
	if err != nil {
		return err
	}
	// Build a candidate separately; missing/corrupt chunks never partially
	// restore totals or hosts. Current capacity may be lower than the saved one.
	hosts := make(map[string]*hostRecord, min(manifest.HostCount, r.capacity))
	seen := make(map[string]bool)
	for index := 0; index < manifest.Chunks; index++ {
		data, found, err := p.store.Load(ctx, counterChunkKey(p.key, manifest.Bank, index))
		if err != nil {
			return err
		}
		var chunk counterChunk
		if !found || len(data) > 1<<20 || json.Unmarshal(data, &chunk) != nil || chunk.ID != manifest.ID || len(chunk.Hosts) != min(hostsPerCounterChunk, manifest.HostCount-index*hostsPerCounterChunk) {
			return errors.New("monitoring counter snapshot is incomplete")
		}
		for _, saved := range chunk.Hosts {
			name := saved.Hostname
			if len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, "\x00\r\n\t /\\@?#") || seen[name] || saved.LastSeen.UnixNano() < 0 || saved.LastSeen.After(time.Now().Add(24*time.Hour)) {
				return errors.New("invalid monitoring host snapshot")
			}
			seen[name] = true
			if len(hosts) >= r.capacity {
				continue
			}
			host := &hostRecord{hostname: name}
			host.counters.restore(saved.Requests, saved.Rejected, saved.CVERejected, saved.IPFirewallRejected, saved.Errors5xx)
			host.bytesIn.Store(saved.BytesIn)
			host.bytesOut.Store(saved.BytesOut)
			host.lastSeen.Store(saved.LastSeen.UnixNano())
			hosts[name] = host
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.hosts = hosts // Start runs before any request or dashboard reader.
	totals := manifest.Totals
	r.totals.restore(totals.Requests, totals.Rejected, totals.CVERejected, totals.IPFirewallRejected, totals.Errors5xx)
	r.untracked.Store(totals.UntrackedRequests)
	p.statusMu.Lock()
	p.status.Restored, p.status.LastSaved, p.status.Error = true, manifest.SavedAt, ""
	p.statusMu.Unlock()
	return nil
}

func (c *counters) restore(requests, rejected, cve, ipFirewall, serverErrors uint64) {
	c.requests.Store(requests)
	c.rejected.Store(rejected)
	c.cveRejected.Store(cve)
	c.ipFirewallRejected.Store(ipFirewall)
	c.errors5xx.Store(serverErrors)
	c.inflight.Store(0)
}

func (r *Registry) saveCounters(ctx context.Context) {
	p := &r.persistence
	ctx, cancel := context.WithTimeout(ctx, counterOperationTimeout)
	defer cancel()
	if err := r.writeCounters(ctx); err != nil {
		if ctx.Err() == context.Canceled {
			return
		}
		p.setError("Redis counter save failed; counters remain active in memory")
		p.logger.Warn("monitoring counter persistence failed; keeping in-memory counters", "error", err)
	}
}

// Two reusable banks bound key growth and preserve the previously published
// snapshot on partial writes. Only publish the manifest after every chunk is
// confirmed. Reads/writes use the synchronous store path, never its async queue.
func (r *Registry) writeCounters(ctx context.Context) error {
	p := &r.persistence
	bank := 0
	previous, found, err := p.store.Load(ctx, p.key)
	if err != nil {
		return err
	}
	if found {
		if manifest, err := decodeCounterManifest(previous); err == nil {
			bank = 1 - manifest.Bank
		}
	}
	hosts, totals := r.Hosts(), r.Totals()
	totals.InFlight = 0
	for i := range hosts {
		hosts[i].InFlight = 0
	}
	now := time.Now().UTC()
	manifest := counterManifest{Version: 1, ID: strconv.FormatInt(now.UnixNano(), 36), Bank: bank, Chunks: (len(hosts) + hostsPerCounterChunk - 1) / hostsPerCounterChunk, HostCount: len(hosts), SavedAt: now, Totals: totals}
	for index := 0; index < manifest.Chunks; index++ {
		start := index * hostsPerCounterChunk
		data, err := json.Marshal(counterChunk{ID: manifest.ID, Hosts: hosts[start:min(start+hostsPerCounterChunk, len(hosts))]})
		if err != nil {
			return err
		}
		if err := p.store.Save(ctx, counterChunkKey(p.key, bank, index), data); err != nil {
			return err
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := p.store.Save(ctx, p.key, data); err != nil {
		return err
	}
	p.statusMu.Lock()
	p.status.LastSaved, p.status.Error = now, ""
	p.statusMu.Unlock()
	return nil
}
