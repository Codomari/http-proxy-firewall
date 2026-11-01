package monitoring

import (
	"math"
	"sync"
	"time"
)

// A nil measurement is unavailable or awaiting a second CPU sample, never zero.
type ResourceSnapshot struct {
	ProcessCPUPercent     *float64 `json:"process_cpu_percent"`
	ProcessResidentBytes  *uint64  `json:"process_resident_bytes"`
	ServerCPUPercent      *float64 `json:"server_cpu_percent"`
	ServerMemoryBytes     *uint64  `json:"server_memory_bytes"`
	ServerMemoryUsedBytes *uint64  `json:"server_memory_used_bytes"`
	ServerMemoryPercent   *float64 `json:"server_memory_percent"`
}

type resourceReading struct {
	processSeconds, totalSeconds, idleSeconds  *float64
	residentBytes, memoryBytes, availableBytes *uint64
}

type resourceSampler struct {
	mu       sync.Mutex
	previous resourceReading
	at       time.Time
	cached   ResourceSnapshot
}

// Sampling is demand-driven and cached for one second across dashboard clients.
// Process CPU uses one full core = 100%; server CPU spans all visible CPUs.
func (s *resourceSampler) snapshot(now time.Time, read func() resourceReading) ResourceSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.at.IsZero() && now.Sub(s.at) < time.Second {
		return s.cached
	}
	current := read()
	result := ResourceSnapshot{ProcessResidentBytes: current.residentBytes, ServerMemoryBytes: current.memoryBytes}
	if current.memoryBytes != nil && current.availableBytes != nil && *current.memoryBytes > 0 {
		used := *current.memoryBytes - min(*current.memoryBytes, *current.availableBytes)
		percent := float64(used) * 100 / float64(*current.memoryBytes)
		result.ServerMemoryUsedBytes, result.ServerMemoryPercent = &used, &percent
	}
	if !s.at.IsZero() && current.processSeconds != nil && s.previous.processSeconds != nil {
		if delta := *current.processSeconds - *s.previous.processSeconds; delta >= 0 {
			percent := delta * 100 / now.Sub(s.at).Seconds()
			result.ProcessCPUPercent = &percent
		}
	}
	if current.totalSeconds != nil && current.idleSeconds != nil && s.previous.totalSeconds != nil && s.previous.idleSeconds != nil {
		total := *current.totalSeconds - *s.previous.totalSeconds
		idle := *current.idleSeconds - *s.previous.idleSeconds
		if total > 0 && idle >= 0 {
			percent := math.Max(0, math.Min(100, (total-idle)*100/total))
			result.ServerCPUPercent = &percent
		}
	}
	s.previous, s.at, s.cached = current, now, result
	return result
}
