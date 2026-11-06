package config

import "errors"

// ConnectionLimits are shared by startup validation and live admin settings.
// The overflow value is an absolute ceiling, not an additional connection count.
type ConnectionLimits struct {
	MaxConcurrentRequests          int  `json:"max_concurrent_requests"`
	UpstreamMaxConnections         int  `json:"upstream_max_connections"`
	UpstreamAllowOverflow          bool `json:"upstream_allow_overflow"`
	UpstreamMaxOverflowConnections int  `json:"upstream_max_overflow_connections"`
}

func ConnectionLimitsFromConfig(c Config) ConnectionLimits {
	return ConnectionLimits{c.HTTP.MaxConcurrentRequests, c.Proxy.MaxConnections, c.Proxy.AllowOverflow, c.Proxy.MaxOverflowConnections}
}

func (limits ConnectionLimits) Validate() error {
	if limits.MaxConcurrentRequests < 1 {
		return errors.New("maximum concurrent requests must be a positive integer")
	}
	return (Proxy{MaxConnections: limits.UpstreamMaxConnections, AllowOverflow: limits.UpstreamAllowOverflow, MaxOverflowConnections: limits.UpstreamMaxOverflowConnections}).ValidateConnectionLimits()
}

func (settings Proxy) ValidateConnectionLimits() error {
	if settings.MaxConnections < 1 {
		return errors.New("PF_UPSTREAM_MAX_CONNECTIONS must be a positive integer")
	}
	if settings.MaxOverflowConnections < 0 {
		return errors.New("PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS cannot be negative")
	}
	if settings.AllowOverflow && settings.MaxOverflowConnections < settings.MaxConnections {
		return errors.New("PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS must be at least PF_UPSTREAM_MAX_CONNECTIONS when overflow is enabled")
	}
	return nil
}
