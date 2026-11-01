package proxy

import (
	"net"
	"sync"
	"sync/atomic"
)

// Registrations exist only between an accepted upgrade and the native server's
// hijack callback. The callback and a connection-abort notification compete for
// the same cleanup owner. Route pools share this registry.
type upgradeHandoffs struct {
	pending sync.Map
	count   atomic.Int64
}

func (h *upgradeHandoffs) register(conn net.Conn, abort func()) {
	h.pending.Store(conn, abort)
	h.count.Add(1)
}

func (h *upgradeHandoffs) take(conn net.Conn) (func(), bool) {
	if h.count.Load() == 0 {
		return nil, false
	}
	value, ok := h.pending.LoadAndDelete(conn)
	if !ok {
		return nil, false
	}
	h.count.Add(-1)
	return value.(func()), true
}

// AbortPendingUpgrade is called by the server for fasthttp.StateClosed. A
// failed pipeline flush or deadline reset can prevent its Hijack callback from
// starting. Ordinary connection closures take only the empty atomic fast path.
func (h *Handler) AbortPendingUpgrade(conn net.Conn) {
	if abort, ok := h.handoffs.take(conn); ok {
		abort()
	}
}
