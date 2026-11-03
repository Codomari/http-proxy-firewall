package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolValue(value bool) *bool { return &value }

func TestYAMLOverridesAndEnvironmentExport(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PF_YAML_TEST_VAR", "")
	os.Unsetenv("PF_YAML_TEST_VAR")
	t.Setenv("PF_LISTEN", "127.0.0.1:9002")
	base := "env:\n  - key: PF_LISTEN\n    value: 127.0.0.1:9000\n  - key: PF_YAML_TEST_VAR\n    value: first\nrules:\n  - type: Behind CloudFlare\n    params:\n      - key: base.example\n        value: true\n      - key: removed.example\n        value: true\ndebug:\n  - host: base.example\n    enabled: true\n    log_file: log/base.log\n"
	override := "env:\n  - key: PF_LISTEN\n    value: 127.0.0.1:9001\n  - key: PF_YAML_TEST_VAR\n    value: second\nrules:\n  - type: Behind CloudFlare\n    params:\n      - key: removed.example\n        value: false\n      - key: new.example\n        value: true\ndebug:\n  - host: base.example\n    enabled: false\n  - host: second.example\n    source: '::ffff:203.0.113.8'\n    enabled: true\n"
	os.WriteFile(DefaultYAML, []byte(base), 0644)
	os.WriteFile(OverrideYAML, []byte(override), 0600)
	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Listen != "127.0.0.1:9002" {
		t.Fatal("process environment did not override YAML")
	}
	if err := cfg.ExportEnvironment(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PF_YAML_TEST_VAR") != "second" || os.Getenv("PF_LISTEN") != "127.0.0.1:9002" {
		t.Fatal("effective YAML values were not exported correctly")
	}
	doc, err := cfg.Source.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || len(doc.Rules[0].Params) != 2 || doc.Rules[0].Params[0].Key != "base.example" || doc.Rules[0].Params[1].Key != "new.example" {
		t.Fatalf("rule merge wrong: %+v", doc.Rules)
	}
	if len(doc.Debug) != 2 || *doc.Debug[0].Enabled || doc.Debug[0].LogFile == nil || *doc.Debug[0].LogFile != "log/base.log" || doc.Debug[1].Source != "203.0.113.8" {
		t.Fatalf("debug field merge wrong: %+v", doc.Debug)
	}
	if err := cfg.Source.SetCloudflareHost("base.example", false); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Source.SetDebug(DebugCapture{Host: "second.example", Source: "203.0.113.8", Enabled: boolValue(false)}); err != nil {
		t.Fatal(err)
	}
	doc, err = cfg.Source.Read()
	if err != nil || len(doc.Rules[0].Params) != 1 || *doc.Debug[1].Enabled {
		t.Fatal("override updates did not remove inherited rule or disable capture")
	}
	data, _ := os.ReadFile(DefaultYAML)
	if string(data) != base {
		t.Fatal("saving overrides changed public defaults")
	}
}

func TestYAMLRejectsAmbiguousOrSecretLeakingConfigurations(t *testing.T) {
	for _, data := range []string{
		"env:\n  - key: REPEATED\n    value: a\n  - key: REPEATED\n    value: b\n",
		"env:\n  - key: BAD-KEY\n    value: data\n", "env:\n  - key: GOOD\n    value: {private-value: data}\n",
		"unknown: private-value\n", "env: []\n---\nenv: []\n", "rules:\n  - type: private-value\n",
		"debug:\n  - host: example.com\n    source: invalid\n", "[private-value]",
	} {
		_, _, err := decodeDocument([]byte(data))
		if err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatalf("invalid YAML accepted or secret exposed: %v", err)
		}
	}
}

func TestLegacyMigrationVerifiesBeforeRemovingOriginals(t *testing.T) {
	dir := t.TempDir()
	env := "REDIS_PASSWORD='private$secret#value'\nPF_PROXY_TO=http://127.0.0.1:7000\nEXTRA_ENV=data\n"
	legacy := "PF_PROXY_TO=--proxy-to=127.0.0.1:8000\nPF_ENABLE_METRICS=--metrics=true\n"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0600)
	os.WriteFile(filepath.Join(dir, "proxy-firewall.conf"), []byte(legacy), 0600)
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	store := NewYAMLStore(filepath.Join(dir, DefaultYAML), filepath.Join(dir, OverrideYAML))
	doc, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	values := doc.Environment()
	if values["REDIS_PASSWORD"] != "private$secret#value" || values["PF_PROXY_TO"] != "127.0.0.1:8000" || values["EXTRA_ENV"] != "data" || values["PF_METRICS"] != "true" {
		t.Fatal("migration lost private values or effective settings")
	}
	data, _ := os.ReadFile(store.OverridePath)
	if !strings.Contains(string(data), "127.0.0.1:7000") {
		t.Fatal("shadowed dotenv value was not retained privately")
	}
	for _, name := range []string{".env", "proxy-firewall.conf"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("legacy file was not removed")
		}
	}
	if err := MigrateLegacy(dir); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(store.OverridePath)
	if string(data) != string(after) {
		t.Fatal("repeated migration changed YAML")
	}
	broken := t.TempDir()
	os.WriteFile(filepath.Join(broken, ".env"), []byte(env), 0600)
	os.WriteFile(filepath.Join(broken, OverrideYAML), []byte("env: [private-value"), 0600)
	if err := MigrateLegacy(broken); err == nil {
		t.Fatal("migration replaced invalid existing YAML")
	}
	retained, _ := os.ReadFile(filepath.Join(broken, ".env"))
	if string(retained) != env {
		t.Fatal("failed migration deleted private configuration")
	}
}
