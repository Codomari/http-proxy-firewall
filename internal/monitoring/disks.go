package monitoring

import (
	"sync"
	"time"
)

type DiskSnapshot struct {
	Mount          string   `json:"mount"`
	Source         string   `json:"source"`
	Filesystem     string   `json:"filesystem"`
	ReadOnly       bool     `json:"read_only"`
	TotalBytes     *uint64  `json:"total_bytes"`
	UsedBytes      *uint64  `json:"used_bytes"`
	AvailableBytes *uint64  `json:"available_bytes"`
	UsedPercent    *float64 `json:"used_percent"`
}

type DiskStatus struct {
	Available bool           `json:"available"`
	Mounts    []DiskSnapshot `json:"mounts"`
}

type diskSampler struct {
	mu     sync.Mutex
	at     time.Time
	cached DiskStatus
}

func (r *Registry) Disks() DiskStatus {
	r.disks.mu.Lock()
	defer r.disks.mu.Unlock()
	now := time.Now()
	if r.disks.at.IsZero() || now.Sub(r.disks.at) >= 5*time.Second {
		r.disks.cached = readDisks()
		r.disks.at = now
	}
	return r.disks.cached
}

func setDiskUsage(d *DiskSnapshot, blocks, free, available, blockSize uint64) {
	if blocks == 0 || blockSize == 0 {
		return
	}
	total := blocks * blockSize
	used := (blocks - min(blocks, free)) * blockSize
	avail := min(blocks, available) * blockSize
	// Match df: reserved blocks are excluded from space available to users.
	percent := float64(0)
	if used+avail > 0 {
		percent = float64(used) * 100 / float64(used+avail)
	}
	d.TotalBytes, d.UsedBytes, d.AvailableBytes, d.UsedPercent = &total, &used, &avail, &percent
}
