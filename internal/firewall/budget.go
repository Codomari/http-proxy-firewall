package firewall

import "sync/atomic"

// byteBudget bounds payload capacity retained by live handlers. Known lengths
// reserve length+1, unknown lengths reserve the configured limit+1, and empty
// bodies retain no reservation. Reservations span downstream processing so a
// slow upstream cannot bypass the bound. This is not a process RSS limit: HTTP
// buffers, transient allocation growth and garbage collection are separate.
type byteBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *byteBudget) acquire(bytes int64) bool {
	for {
		used := b.used.Load()
		if bytes < 0 || bytes > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+bytes) {
			return true
		}
	}
}

func (b *byteBudget) release(bytes int64) { b.used.Add(-bytes) }
