package storage

import "time"

type Snapshot struct {
	Enabled     bool       `json:"enabled"`
	Status      string     `json:"status"`
	Reads       uint64     `json:"reads"`
	Writes      uint64     `json:"writes"`
	ReadErrors  uint64     `json:"read_errors"`
	WriteErrors uint64     `json:"write_errors"`
	QueueDepth  int        `json:"queue_depth"`
	LastSuccess *time.Time `json:"last_success"`
}

// Snapshot observes existing state. It never connects, pings or queries Redis.
// Counters count attempted backend operations, excluding local/circuit fallbacks.
func (r *Remote) Snapshot() Snapshot {
	r.mx.Lock()
	enabled, started, stopped, queued := r.cfg.Enabled, r.started, r.stopped, len(r.queue)
	r.mx.Unlock()
	result := Snapshot{Enabled: enabled, Status: "disabled", Reads: r.reads.Load(), Writes: r.writes.Load(), ReadErrors: r.readErrors.Load(), WriteErrors: r.writeErrors.Load(), QueueDepth: queued}
	if stamp := r.lastSuccess.Load(); stamp != 0 {
		last := time.Unix(0, stamp).UTC()
		result.LastSuccess = &last
	}
	switch {
	case !enabled:
	case stopped:
		result.Status = "stopped"
	case !started:
		result.Status = "not_started"
	case r.unavailableUntil.Load() != 0:
		result.Status = "unavailable"
	case result.LastSuccess == nil:
		result.Status = "not_checked"
	default:
		result.Status = "available"
	}
	return result
}
