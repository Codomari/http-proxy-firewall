package firewall

import (
	"math"
	"strings"
	"sync"
	"time"

	"http-proxy-firewall/internal/cache"
)

type hostWindow struct {
	start        time.Time
	penaltyUntil time.Time
	count        uint64
}

// detector updates the window, counter and penalty in one critical section.
// Lazy expiry replaces reset goroutines and keeps all retained hosts bounded.
type detector struct {
	mu        sync.Mutex
	hosts     *cache.Cache[string, hostWindow]
	window    time.Duration
	penalty   time.Duration
	threshold uint64
}

func (d *detector) penalized(host string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.hosts.Get(host, now)
	if ok && now.Before(state.penaltyUntil) {
		return true
	}
	if !ok || !now.Before(state.start.Add(d.window)) {
		state = hostWindow{start: now}
	}
	if state.count != math.MaxUint64 {
		state.count++
	}
	// Preserve v1's per-second average over the fixed sampling window.
	seconds := uint64(d.window / time.Second)
	if state.count/seconds > d.threshold {
		state.penaltyUntil = now.Add(d.penalty)
	}
	expires := state.start.Add(d.window)
	if state.penaltyUntil.After(expires) {
		expires = state.penaltyUntil
	}
	// Cache.Set preserves an existing entry's owned key. A new entry needs a
	// clone because Fiber strings may alias storage reused by the next request.
	if !ok {
		host = strings.Clone(host)
	}
	d.hosts.Set(host, state, expires, now)
	return now.Before(state.penaltyUntil)
}
