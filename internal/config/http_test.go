package config

import (
	"io"
	"testing"
	"time"
)

func TestHTTPProtocolAndIdleTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		values  map[string]string
		args    []string
		http2   bool
		timeout time.Duration
	}{
		{"defaults", nil, nil, false, 15 * time.Second},
		{"enable HTTP2", map[string]string{"PF_HTTP2_ENABLE": "true", "PF_IDLE_REQUEST_TIMEOUT": "5s"}, nil, true, 5 * time.Second},
		{"legacy timeout", map[string]string{"PF_IDLE_TIMEOUT": "10s"}, nil, false, 10 * time.Second},
		{"canonical timeout wins", map[string]string{"PF_IDLE_TIMEOUT": "1m", "PF_IDLE_REQUEST_TIMEOUT": "15s"}, nil, false, 15 * time.Second},
		{"flags", map[string]string{"PF_HTTP2_ENABLE": "true", "PF_IDLE_REQUEST_TIMEOUT": "1m"}, []string{"--http2-enable=false", "--idle-request-timeout=15s"}, false, 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.args, tc.values, io.Discard)
			if err != nil || cfg.HTTP.HTTP2Enable != tc.http2 || cfg.HTTP.IdleTimeout != tc.timeout {
				t.Fatalf("unexpected HTTP settings: %+v %v", cfg.HTTP, err)
			}
		})
	}
	for _, values := range []map[string]string{
		{"PF_HTTP2_ENABLE": "invalid"}, {"PF_IDLE_REQUEST_TIMEOUT": "0s"},
		{"PF_IDLE_REQUEST_TIMEOUT": "-1s"}, {"PF_IDLE_REQUEST_TIMEOUT": "invalid"},
	} {
		if _, err := Parse(nil, values, io.Discard); err == nil {
			t.Fatalf("invalid HTTP settings accepted: %v", values)
		}
	}
}

func TestHTTPSettingsAndLegacyProcessOverrides(t *testing.T) {
	values := map[string]string{"PF_IDLE_REQUEST_TIMEOUT": "15s"}
	if err := mergeDeploymentValues(values, map[string]string{"PF_IDLE_TIMEOUT": "5s"}); err != nil || values["PF_IDLE_REQUEST_TIMEOUT"] != "5s" {
		t.Fatal("legacy process timeout did not override YAML timeout")
	}
	cfg := Defaults()
	for _, change := range []func(*Config){
		func(next *Config) { next.HTTP.HTTP2Enable = true },
		func(next *Config) { next.HTTP.IdleTimeout = 5 * time.Second },
	} {
		next := cfg
		change(&next)
		if changes := cfg.RestartChanges(next); len(changes) != 1 || changes[0] != "HTTP listeners and timeouts" {
			t.Fatalf("HTTP edit did not request a restart: %v", changes)
		}
	}
}
