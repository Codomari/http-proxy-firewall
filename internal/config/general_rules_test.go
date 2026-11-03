package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestGeneralRulesPreserveUnrelatedYAMLData(t *testing.T) {
	original := `# private deployment settings
env:
  - key: REDIS_PASSWORD
    value: "private$token#value"
  - key: MULTILINE
    value: |
      first line
      IP_FILTER_WHITELIST=do-not-touch-this-secret-line
      last line
  - key: IP_FILTER_WHITELIST
    value: "198.51.100.1" # retain this comment
  - key: IP_FILTER_ALLOWED_COUNTRIES
    value: Turkey
rules: []
debug: []
`
	path := filepath.Join(t.TempDir(), OverrideYAML)
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	file := GeneralRulesFile{Path: path}
	settings := GeneralRules{WhitelistIPs: []string{"203.0.113.8", "::ffff:203.0.113.8", "2001:db8::8"}, WhitelistNetworks: []string{"203.0.113.9/24"}, AllowedCountries: []string{" Azerbaijan ", "Turkey", "turkey"}, IPCheckpoint: true, CountryCheckpoint: false, DDoSThreshold: 350}
	if err := file.Save(settings); err != nil {
		t.Fatal(err)
	}
	got, err := file.Read()
	want, _ := settings.Normalize()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("settings did not round trip: got=%+v err=%v", got, err)
	}
	data, _ := os.ReadFile(path)
	for _, text := range []string{"# private deployment settings", "private$token#value", "IP_FILTER_WHITELIST=do-not-touch-this-secret-line", "# retain this comment"} {
		if !strings.Contains(string(data), text) {
			t.Fatalf("unrelated YAML data changed: %q", text)
		}
	}
	var before, after Document
	if yaml.Unmarshal([]byte(original), &before) != nil || yaml.Unmarshal(data, &after) != nil {
		t.Fatal("invalid YAML")
	}
	if before.Environment()["MULTILINE"] != after.Environment()["MULTILINE"] {
		t.Fatal("multiline private value changed")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatal("file permissions changed")
	}
	if err := file.Save(got); err != nil {
		t.Fatal(err)
	}
	repeated, _ := os.ReadFile(path)
	if string(data) != string(repeated) {
		t.Fatal("repeated save changed YAML")
	}
}

func TestGeneralRulesRejectInvalidInputsAndUnsafeFiles(t *testing.T) {
	for _, rules := range []GeneralRules{
		{WhitelistIPs: []string{"203.0.113.1/24"}, DDoSThreshold: 200}, {WhitelistIPs: []string{"fe80::1%eth0"}, DDoSThreshold: 200},
		{WhitelistNetworks: []string{"not-a-network"}, DDoSThreshold: 200}, {AllowedCountries: []string{"Turkey\nREDIS_PASSWORD=changed"}, DDoSThreshold: 200},
		{DDoSThreshold: 0}, {DDoSThreshold: 1_000_000_001},
	} {
		if _, err := rules.Normalize(); err == nil {
			t.Fatalf("invalid settings accepted: %+v", rules)
		}
	}
	path := filepath.Join(t.TempDir(), OverrideYAML)
	file := GeneralRulesFile{Path: path}
	rules, err := file.Read()
	if err != nil || !rules.IPCheckpoint || !rules.CountryCheckpoint {
		t.Fatal("missing file did not produce enabled checkpoint defaults")
	}
	if err := file.Save(rules); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("new override file is not private")
	}
	broken := "env: [private-value"
	os.WriteFile(path, []byte(broken), 0600)
	if err := file.Save(rules); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("invalid YAML content was saved or leaked in error")
	}
	data, _ := os.ReadFile(path)
	if string(data) != broken {
		t.Fatal("failed save changed override YAML")
	}
	link := filepath.Join(t.TempDir(), OverrideYAML)
	os.Symlink(path, link)
	file.Path = link
	if err := file.Save(rules); err == nil {
		t.Fatal("save followed a symlink")
	}
}
