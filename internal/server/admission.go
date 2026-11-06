package server

import (
	"http-proxy-firewall/internal/config"
	"sync"
)

type requestAdmission struct {
	mu            sync.Mutex
	active, limit int
}

func (admission *requestAdmission) acquire() bool {
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.active >= admission.limit {
		return false
	}
	admission.active++
	return true
}

func (admission *requestAdmission) release() {
	admission.mu.Lock()
	admission.active--
	admission.mu.Unlock()
}

// SetConnectionLimits updates request admission and every upstream pool while
// allowing existing requests and tunnels to finish after a reduction.
func (s *Server) SetConnectionLimits(limits config.ConnectionLimits) {
	if limits.Validate() != nil {
		return
	}
	s.admission.mu.Lock()
	s.admission.limit = limits.MaxConcurrentRequests
	s.admission.mu.Unlock()
	s.upstream.SetConnectionLimits(limits)
}
