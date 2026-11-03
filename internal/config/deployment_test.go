package config

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyDeploymentSettings(t *testing.T) {
	legacy := map[string]string{
		"PF_LISTEN_AT":          "--listen=127.0.0.1:8181",
		"PF_PROXY_TO":           "--proxy-to=127.0.0.1:9000",
		"PF_ENABLE_METRICS":     "--metrics=true",
		"PF_ENABLE_SILENT_MODE": "--silent=false",
		"PF_ENABLE_REDIS":       "--enable-redis=false",
	}
	original := make(map[string]string)
	for key, value := range legacy {
		original[key] = value
	}
	values := make(map[string]string)
	if err := mergeDeploymentValues(values, legacy); err != nil {
		t.Fatal(err)
	}
	c, err := Parse(nil, values, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Listen != "127.0.0.1:8181" || c.Proxy.Upstream != "http://127.0.0.1:9000" || !c.Observability.Metrics || c.Observability.Silent || c.Redis.Enabled {
		t.Fatal("legacy deployment settings were not applied")
	}
	if !reflect.DeepEqual(legacy, original) {
		t.Fatal("source settings were modified")
	}
}

func TestDeploymentAliases(t *testing.T) {
	values := make(map[string]string)
	if err := mergeDeploymentValues(values, map[string]string{
		"PF_LISTEN_AT":      "--listen=127.0.0.1:8181",
		"PF_LISTEN":         "127.0.0.1:8282",
		"PF_ENABLE_METRICS": "--metrics",
		"PF_ENABLE_REDIS":   "true",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := Parse(nil, values, io.Discard)
	if err != nil || c.HTTP.Listen != "127.0.0.1:8282" || !c.Observability.Metrics || !c.Redis.Enabled {
		t.Fatal("plain settings or legacy boolean flags were not applied")
	}
	for _, key := range []string{"PF_LISTEN_AT", "PF_PROXY_TO", "PF_ENABLE_METRICS", "PF_ENABLE_SILENT_MODE", "PF_ENABLE_REDIS"} {
		err := mergeDeploymentValues(values, map[string]string{key: "--unexpected=do-not-echo"})
		if err == nil || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("unexpected legacy flag accepted or its value exposed")
		}
	}
}

func TestLoadDeploymentFilesAndPrecedence(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, key := range []string{"PF_LISTEN", "PF_LISTEN_AT", "PF_PROXY_TO", "PF_ENABLE_METRICS", "PF_METRICS", "PF_ENABLE_SILENT_MODE", "PF_SILENT", "PF_ENABLE_REDIS"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		DefaultYAML:  "env:\n  - key: PF_LISTEN\n    value: 127.0.0.1:8181\n  - key: PF_PROXY_TO\n    value: http://127.0.0.1:9000\n  - key: PF_METRICS\n    value: false\n",
		OverrideYAML: "env:\n  - key: PF_LISTEN\n    value: 127.0.0.1:8282\n  - key: PF_PROXY_TO\n    value: http://127.0.0.1:9001\n  - key: PF_METRICS\n    value: true\n",
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(nil, io.Discard)
	if err != nil || c.HTTP.Listen != "127.0.0.1:8282" || c.Proxy.Upstream != "http://127.0.0.1:9001" || !c.Observability.Metrics {
		t.Fatalf("deployment file precedence failed: %v", err)
	}
	t.Setenv("PF_PROXY_TO", "http://127.0.0.1:9002")
	c, err = Load(nil, io.Discard)
	if err != nil || c.Proxy.Upstream != "http://127.0.0.1:9002" {
		t.Fatalf("process environment precedence failed: %v", err)
	}
	c, err = Load([]string{"--proxy-to=127.0.0.1:9003"}, io.Discard)
	if err != nil || c.Proxy.Upstream != "http://127.0.0.1:9003" {
		t.Fatalf("command-line precedence failed: %v", err)
	}
	// systemd EnvironmentFile exports the original flag-valued settings too.
	t.Setenv("PF_PROXY_TO", "--proxy-to=127.0.0.1:9004")
	c, err = Load(nil, io.Discard)
	if err != nil || c.Proxy.Upstream != "http://127.0.0.1:9004" {
		t.Fatalf("legacy process environment failed: %v", err)
	}
	for name, content := range files {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != content {
			t.Fatalf("protected deployment file changed: %s", name)
		}
	}
}
