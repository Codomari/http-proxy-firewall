package config

import (
	"io"
	"math"
	"os"
	"reflect"
	"runtime/debug"
	"testing"
)

func TestRuntimeGCParsingAndApplication(t *testing.T) {
	for _, tc := range []struct {
		gc, memory string
		percent    int
		limit      int64
	}{
		{"", "", 100, math.MaxInt64}, {"50", "512MiB", 50, 512 << 20},
		{"off", "1GiB", -1, 1 << 30}, {"0", "1024KiB", 0, 1 << 20},
		{"100", "4096", 100, 4096}, {"100", "2048B", 100, 2048}, {"100", "1TiB", 100, 1 << 40},
	} {
		got, err := RuntimeFromValues(map[string]string{"GOGC": tc.gc, "GOMEMLIMIT": tc.memory})
		if err != nil || got.GCPercent != tc.percent || got.MemoryLimitBytes != tc.limit {
			t.Fatalf("%+v: %+v %v", tc, got, err)
		}
	}
	for _, values := range []map[string]string{
		{"GOGC": "-1"}, {"GOGC": "1.5"}, {"GOGC": "invalid"},
		{"GOMEMLIMIT": "0"}, {"GOMEMLIMIT": "-1"}, {"GOMEMLIMIT": "1.5GiB"},
		{"GOMEMLIMIT": "1GB"}, {"GOMEMLIMIT": "9223372036854775807TiB"},
	} {
		if _, err := Parse(nil, values, io.Discard); err == nil {
			t.Fatalf("invalid GC settings accepted: %v", values)
		}
	}
	previousGC, previousLimit := debug.SetGCPercent(100), debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetGCPercent(previousGC); debug.SetMemoryLimit(previousLimit) })
	Runtime{GCPercent: 50, MemoryLimitBytes: 512 << 20}.Apply()
	if debug.SetGCPercent(100) != 50 || debug.SetMemoryLimit(-1) != 512<<20 {
		t.Fatal("YAML runtime settings were not applied")
	}
}

func TestReloadDetectsGCChangesWithoutStaleExportedEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, key := range []string{"GOGC", "GOMEMLIMIT"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	if err := os.WriteFile(DefaultYAML, []byte("env:\n  - key: GOGC\n    value: '100'\n  - key: GOMEMLIMIT\n    value: off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load([]string{"--tls=false"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ExportEnvironment(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Source.UpdateEnvironment(map[string]string{"GOMEMLIMIT": "512MiB"}); err != nil {
		t.Fatal(err)
	}
	next, err := cfg.Reload()
	if err != nil || next.Runtime.MemoryLimitBytes != 512<<20 || !reflect.DeepEqual(cfg.RestartChanges(next), []string{"Garbage collection"}) {
		t.Fatalf("reload failed: %+v %v %v", next.Runtime, cfg.RestartChanges(next), err)
	}
	if err := cfg.Source.UpdateEnvironment(map[string]string{"GOMEMLIMIT": "off"}); err != nil {
		t.Fatal(err)
	}
	next, err = cfg.Reload()
	if err != nil || len(cfg.RestartChanges(next)) != 0 {
		t.Fatal("reverting settings did not clear restart flag")
	}
	t.Setenv("GOMEMLIMIT", "1GiB")
	pinned, err := Load([]string{"--tls=false"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned.Source.UpdateEnvironment(map[string]string{"GOMEMLIMIT": "768MiB"}); err != nil {
		t.Fatal(err)
	}
	next, err = pinned.Reload()
	if err != nil || len(pinned.RestartChanges(next)) != 0 || next.Runtime.MemoryLimitBytes != 1<<30 {
		t.Fatal("process override caused an unnecessary restart")
	}
}

func TestBodyDefaultsAndLiveSettingsDoNotRequireRestart(t *testing.T) {
	cfg := Defaults()
	if cfg.Firewall.MaxBodyBytes != 200<<20 {
		t.Fatal("default request body limit is not 200 MiB")
	}
	next := cfg
	next.Firewall.MaxBodyBytes = 100 << 20
	next.Proxy.RequestRetryTimes++
	next.HTTP.MaxConcurrentRequests++
	if len(cfg.RestartChanges(next)) != 0 {
		t.Fatal("live settings requested a restart")
	}
	next.Firewall.MaxBufferedBytes++
	if len(cfg.RestartChanges(next)) != 1 {
		t.Fatal("startup-only settings did not request a restart")
	}
}
