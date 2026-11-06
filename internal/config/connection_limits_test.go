package config

import (
	"io"
	"testing"
)

func TestConnectionLimitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		env   map[string]string
		valid bool
	}{
		{nil, true},
		{map[string]string{"PF_UPSTREAM_MAX_CONNECTIONS": "1024"}, true},
		{map[string]string{"PF_UPSTREAM_ALLOW_OVERFLOW": "true", "PF_UPSTREAM_MAX_CONNECTIONS": "256", "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "512"}, true},
		{map[string]string{"PF_UPSTREAM_ALLOW_OVERFLOW": "true", "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "256"}, true},
		{map[string]string{"PF_UPSTREAM_ALLOW_OVERFLOW": "true", "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "128"}, false},
		{map[string]string{"PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "-1"}, false},
		{map[string]string{"PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": "1.5"}, false},
		{map[string]string{"PF_UPSTREAM_ALLOW_OVERFLOW": "maybe"}, false},
		{map[string]string{"PF_UPSTREAM_MAX_CONNECTIONS": "0"}, false},
		{map[string]string{"PF_MAX_CONCURRENT_REQUESTS": "0"}, false},
	} {
		if _, err := Parse(nil, tc.env, io.Discard); (err == nil) != tc.valid {
			t.Fatalf("valid=%v err=%v", tc.valid, err)
		}
	}
	cfg, err := Parse([]string{"--upstream-allow-overflow", "--upstream-max-connections=2", "--upstream-max-overflow-connections=4", "--max-concurrent-requests=6"}, nil, io.Discard)
	if err != nil || !cfg.Proxy.AllowOverflow || cfg.Proxy.MaxConnections != 2 || cfg.Proxy.MaxOverflowConnections != 4 || cfg.HTTP.MaxConcurrentRequests != 6 {
		t.Fatal("connection flags did not apply", err)
	}
}
