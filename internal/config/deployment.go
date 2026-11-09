package config

import (
	"fmt"
	"strings"
)

// Translate the original service's flag-valued settings without evaluating shell code.
func mergeDeploymentValues(destination, source map[string]string) error {
	values := make(map[string]string, len(source))
	for key, value := range source {
		values[key] = value
	}
	// Keep the old name as a fallback within each configuration layer.
	if value, ok := values["PF_IDLE_TIMEOUT"]; ok {
		if _, explicit := values["PF_IDLE_REQUEST_TIMEOUT"]; !explicit {
			values["PF_IDLE_REQUEST_TIMEOUT"] = value
		}
		delete(values, "PF_IDLE_TIMEOUT")
	}
	for _, setting := range []struct {
		legacy, current, flag string
		boolean               bool
	}{
		{"PF_LISTEN_AT", "PF_LISTEN", "--listen", false},
		{"PF_PROXY_TO", "PF_PROXY_TO", "--proxy-to", false},
		{"PF_ENABLE_METRICS", "PF_METRICS", "--metrics", true},
		{"PF_ENABLE_SILENT_MODE", "PF_SILENT", "--silent", true},
		{"PF_ENABLE_REDIS", "PF_ENABLE_REDIS", "--enable-redis", true},
	} {
		value, ok := values[setting.legacy]
		if !ok {
			continue
		}
		if setting.legacy != setting.current {
			delete(values, setting.legacy)
			if _, explicit := values[setting.current]; explicit || value == "" {
				continue
			}
		}
		switch {
		case strings.HasPrefix(value, setting.flag+"="):
			value = strings.TrimPrefix(value, setting.flag+"=")
		case setting.boolean && value == setting.flag:
			value = "true"
		case strings.HasPrefix(value, "--"):
			return fmt.Errorf("%s requires a plain value or %s=value", setting.legacy, setting.flag)
		}
		values[setting.current] = value
	}
	for key, value := range values {
		destination[key] = value
	}
	return nil
}
