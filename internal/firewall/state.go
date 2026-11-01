package firewall

import "time"

// DDoSState observes the current fixed penalty without counting an admin read
// as traffic or creating a detector entry. WWW and bare names share v1 state.
func (e *Engine) DDoSState(host string) (bool, time.Time) {
	name, err := normalizeHostname(host)
	if err != nil {
		return false, time.Time{}
	}
	now := e.now()
	state, ok := e.detector.hosts.Get(name, now)
	if !ok || !now.Before(state.penaltyUntil) {
		return false, time.Time{}
	}
	return true, state.penaltyUntil
}
