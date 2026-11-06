package proxy

import (
	"http-proxy-firewall/internal/config"
	"sync"
)

// Reservations span the entire response/tunnel. Limits may change without
// replacing a channel or losing ownership of requests already in progress.
type connectionSlots struct {
	mu               sync.Mutex
	normal, overflow int
	base, ceiling    int
	allowOverflow    bool
}

func (slots *connectionSlots) acquire() (overflow, ok bool) {
	slots.mu.Lock()
	defer slots.mu.Unlock()
	limit := slots.base
	if slots.allowOverflow {
		limit = slots.ceiling
	}
	if slots.normal+slots.overflow >= limit {
		return false, false
	}
	if slots.normal < slots.base {
		slots.normal++
		return false, true
	}
	slots.overflow++
	return true, true
}

func (slots *connectionSlots) release(overflow bool) (trimIdle bool) {
	slots.mu.Lock()
	defer slots.mu.Unlock()
	if overflow {
		slots.overflow--
	} else {
		trimIdle = slots.normal > slots.base
		slots.normal--
	}
	return trimIdle
}

func (slots *connectionSlots) InUse() int {
	slots.mu.Lock()
	defer slots.mu.Unlock()
	return slots.normal + slots.overflow
}

// SetConnectionLimits applies to the default pool and every host route.
// Reductions drain active requests; idle surplus is discarded immediately.
func (h *Handler) SetConnectionLimits(limits config.ConnectionLimits) {
	settings := config.Proxy{MaxConnections: limits.UpstreamMaxConnections, AllowOverflow: limits.UpstreamAllowOverflow, MaxOverflowConnections: limits.UpstreamMaxOverflowConnections}
	if settings.ValidateConnectionLimits() != nil {
		return
	}
	h.slots.mu.Lock()
	previousBase, previousCeiling := h.slots.base, h.slots.base
	if h.slots.allowOverflow {
		previousCeiling = h.slots.ceiling
	}
	ceiling := settings.MaxConnections
	if settings.AllowOverflow {
		ceiling = settings.MaxOverflowConnections
	}
	h.client.SetMaxConns(ceiling)
	h.slots.base, h.slots.ceiling, h.slots.allowOverflow = settings.MaxConnections, settings.MaxOverflowConnections, settings.AllowOverflow
	h.slots.mu.Unlock()
	if settings.MaxConnections < previousBase || ceiling < previousCeiling {
		h.client.CloseIdleConnections()
	}
	for _, route := range h.routes {
		route.SetConnectionLimits(limits)
	}
}
