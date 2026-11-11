// Package monitoring maintains bounded, process-local dashboard statistics.
// Byte counts describe decoded payloads, not HTTP headers or wire framing.
package monitoring

import (
	"errors"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"

	"http-proxy-firewall/internal/config"
)

type HostSnapshot struct {
	Hostname           string    `json:"hostname"`
	Requests           uint64    `json:"requests"`
	InFlight           uint64    `json:"inflight"`
	Rejected           uint64    `json:"rejected"`
	CVERejected        uint64    `json:"cve_rejected"`
	IPFirewallRejected uint64    `json:"ip_firewall_rejected"`
	Errors5xx          uint64    `json:"errors_5xx"`
	BytesIn            uint64    `json:"bytes_in"`
	BytesOut           uint64    `json:"bytes_out"`
	LastSeen           time.Time `json:"last_seen"`
}

type TotalsSnapshot struct {
	Requests           uint64 `json:"requests"`
	InFlight           uint64 `json:"inflight"`
	Rejected           uint64 `json:"rejected"`
	CVERejected        uint64 `json:"cve_rejected"`
	IPFirewallRejected uint64 `json:"ip_firewall_rejected"`
	Errors5xx          uint64 `json:"errors_5xx"`
	TrackedHosts       int    `json:"tracked_hosts"`
	UntrackedRequests  uint64 `json:"untracked_requests"`
	Capacity           int    `json:"capacity"`
}

type RuntimeSnapshot struct {
	ResourceSnapshot
	UptimeSeconds      float64 `json:"uptime_seconds"`
	Goroutines         int     `json:"goroutines"`
	HeapAllocatedBytes uint64  `json:"heap_allocated_bytes"`
	HeapInUseBytes     uint64  `json:"heap_in_use_bytes"`
	StackBytes         uint64  `json:"stack_bytes"`
	SystemBytes        uint64  `json:"system_bytes"`
	GCCount            uint32  `json:"gc_count"`
	GCPauseTotalNS     uint64  `json:"gc_pause_total_ns"`
	GCHeapGoalBytes    uint64  `json:"gc_heap_goal_bytes"`
	GCMemoryLimitBytes int64   `json:"gc_memory_limit_bytes"`
	CPUCount           int     `json:"cpu_count"`
	GOMAXPROCS         int     `json:"gomaxprocs"`
}

type counters struct {
	requests           atomic.Uint64
	inflight           atomic.Uint64
	rejected           atomic.Uint64
	cveRejected        atomic.Uint64
	ipFirewallRejected atomic.Uint64
	errors5xx          atomic.Uint64
}

type hostRecord struct {
	hostname string
	counters
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	lastSeen atomic.Int64
}

type Registry struct {
	enabled     bool
	capacity    int
	started     time.Time
	mu          sync.RWMutex
	hosts       map[string]*hostRecord
	totals      counters
	untracked   atomic.Uint64
	resources   resourceSampler
	disks       diskSampler
	persistence counterPersistence
}

func New(cfg config.Config) *Registry {
	capacity := cfg.Admin.MaxHosts
	if capacity <= 0 {
		capacity = 10000
	}
	return &Registry{enabled: cfg.Admin.Enabled, capacity: capacity, started: time.Now(), hosts: make(map[string]*hostRecord)}
}

func (r *Registry) Middleware(normalize func(string) (string, error)) fiber.Handler {
	if !r.enabled {
		return func(c fiber.Ctx) error { return c.Next() }
	}
	return func(c fiber.Ctx) (err error) {
		var host *hostRecord
		if normalize != nil {
			if name, normalizeErr := normalize(string(c.Request().Header.Host())); normalizeErr == nil && name != "" && len(name) <= 253 {
				host = r.findHost(name)
			}
		}
		if host == nil {
			r.untracked.Add(1)
		}
		r.totals.requests.Add(1)
		r.totals.inflight.Add(1)
		if host != nil {
			host.requests.Add(1)
			host.inflight.Add(1)
			markSeen(host, time.Now())
		}
		owned := &completion{registry: r, host: host}
		c.Locals(completionKey{}, owned)
		returned := false
		defer func() {
			if !returned {
				owned.finish(fiber.StatusInternalServerError, 0)
			}
		}()
		err = c.Next()
		status := c.Response().StatusCode()
		if err != nil {
			status = fiber.StatusInternalServerError
			var ferr *fiber.Error
			if errors.As(err, &ferr) {
				status = ferr.Code
			}
			owned.finish(status, 0)
		} else if !owned.asynchronous.Load() {
			bytesOut := uint64(0)
			if !c.Response().SkipBody && !c.Request().Header.IsHead() && !c.Response().IsBodyStream() {
				bytesOut = uint64(len(c.Response().Body()))
			}
			owned.finish(status, bytesOut)
		}
		returned = true
		return err
	}
}

type ipFirewallRejectionKey struct{}

// RecordIPFirewallRejection accounts for early 444 responses that never enter
// request monitoring. Each increments requests, 4xx and IP Firewall rejections,
// without counting payload bytes or leaving an in-flight request.
func (r *Registry) RecordIPFirewallRejection(c fiber.Ctx, normalize func(string) (string, error)) {
	if !r.enabled || c.Locals(ipFirewallRejectionKey{}) != nil {
		return
	}
	c.Locals(ipFirewallRejectionKey{}, true)
	r.totals.requests.Add(1)
	r.totals.ipFirewallRejected.Add(1)
	r.totals.rejected.Add(1)
	if normalize != nil {
		if name, err := normalize(string(c.Request().Header.Host())); err == nil && name != "" && len(name) <= 253 {
			if host := r.findHost(name); host != nil {
				host.requests.Add(1)
				host.ipFirewallRejected.Add(1)
				host.rejected.Add(1)
				markSeen(host, time.Now())
				return
			}
		}
	}
	r.untracked.Add(1)
}

func (r *Registry) findHost(name string) *hostRecord {
	r.mu.RLock()
	host := r.hosts[name]
	r.mu.RUnlock()
	if host != nil {
		return host
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if host = r.hosts[name]; host != nil {
		return host
	}
	if len(r.hosts) >= r.capacity {
		return nil
	}
	owned := strings.Clone(name)
	host = &hostRecord{hostname: owned}
	r.hosts[owned] = host
	return host
}

func (r *Registry) Hosts() []HostSnapshot {
	r.mu.RLock()
	hosts := make([]*hostRecord, 0, len(r.hosts))
	for _, host := range r.hosts {
		hosts = append(hosts, host)
	}
	r.mu.RUnlock()
	result := make([]HostSnapshot, 0, len(hosts))
	for _, host := range hosts {
		result = append(result, HostSnapshot{
			Hostname: host.hostname, Requests: host.requests.Load(), InFlight: host.inflight.Load(),
			Rejected: host.rejected.Load(), CVERejected: host.cveRejected.Load(), Errors5xx: host.errors5xx.Load(),
			IPFirewallRejected: host.ipFirewallRejected.Load(),
			BytesIn:            host.bytesIn.Load(), BytesOut: host.bytesOut.Load(), LastSeen: time.Unix(0, host.lastSeen.Load()).UTC(),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Requests != result[j].Requests {
			return result[i].Requests > result[j].Requests
		}
		return result[i].Hostname < result[j].Hostname
	})
	return result
}

func (r *Registry) Totals() TotalsSnapshot {
	r.mu.RLock()
	tracked := len(r.hosts)
	r.mu.RUnlock()
	return TotalsSnapshot{
		Requests: r.totals.requests.Load(), InFlight: r.totals.inflight.Load(), Rejected: r.totals.rejected.Load(), Errors5xx: r.totals.errors5xx.Load(),
		CVERejected: r.totals.cveRejected.Load(), TrackedHosts: tracked, UntrackedRequests: r.untracked.Load(), Capacity: r.capacity,
		IPFirewallRejected: r.totals.ipFirewallRejected.Load(),
	}
}

func (r *Registry) Runtime() RuntimeSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return RuntimeSnapshot{
		ResourceSnapshot: r.resources.snapshot(time.Now(), readResources),
		UptimeSeconds:    time.Since(r.started).Seconds(), Goroutines: runtime.NumGoroutine(),
		HeapAllocatedBytes: memory.HeapAlloc, HeapInUseBytes: memory.HeapInuse,
		StackBytes: memory.StackInuse, SystemBytes: memory.Sys,
		GCCount: memory.NumGC, GCPauseTotalNS: memory.PauseTotalNs,
		GCHeapGoalBytes: memory.NextGC, GCMemoryLimitBytes: debug.SetMemoryLimit(-1),
		CPUCount: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
}

func markSeen(host *hostRecord, now time.Time) {
	stamp := now.UnixNano()
	for {
		previous := host.lastSeen.Load()
		if stamp <= previous || host.lastSeen.CompareAndSwap(previous, stamp) {
			return
		}
	}
}
