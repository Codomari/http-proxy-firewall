package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestGeneralRulesPreserveUnrelatedDotenvData(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(strings.ReplaceAll(newline, "\n", "LF"), func(t *testing.T) {
			original := strings.Join([]string{
				"# private deployment settings",
				`REDIS_PASSWORD="private$token#value"`,
				"MULTILINE='first line",
				"IP_FILTER_WHITELIST=do-not-touch-this-secret-line",
				"last line'",
				`export IP_FILTER_WHITELIST = "198.51.100.1" # retain this comment`,
				"IP_FILTER_WHITELIST=198.51.100.2",
				"IP_FILTER_WHITELIST_NETWORKS: '198.51.100.0/24'",
				"IP_FILTER_ALLOWED_COUNTRIES='Turkey'",
				"# final comment",
			}, newline)
			path := filepath.Join(t.TempDir(), ".env")
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
				t.Fatalf("settings did not round trip: got=%+v want=%+v err=%v", got, want, err)
			}
			data, _ := os.ReadFile(path)
			for _, unchanged := range []string{`REDIS_PASSWORD="private$token#value"`, "MULTILINE='first line" + newline + "IP_FILTER_WHITELIST=do-not-touch-this-secret-line" + newline + "last line'", " # retain this comment", "# final comment"} {
				if !strings.Contains(string(data), unchanged) {
					t.Fatalf("unrelated dotenv data changed: %q", unchanged)
				}
			}
			if newline == "\r\n" && strings.Contains(strings.ReplaceAll(string(data), "\r\n", ""), "\n") {
				t.Fatal("CRLF file acquired mixed line endings")
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 {
				t.Fatal("existing .env permissions changed")
			}
			values, err := godotenv.Unmarshal(string(data))
			if err != nil || values["IP_FILTER_WHITELIST"] != "203.0.113.8,2001:db8::8" || values["IP_FILTER_WHITELIST_NETWORKS"] != "203.0.113.0/24" {
				t.Fatal("normalized dotenv values were not persisted")
			}
			if err := file.Save(got); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(data) {
				t.Fatal("repeated save changed unrelated configuration or duplicated settings")
			}
		})
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
	path := filepath.Join(t.TempDir(), ".env")
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
		t.Fatal("new dotenv file is not private")
	}
	broken := "SECRET='unterminated-private-value"
	os.WriteFile(path, []byte(broken), 0600)
	if err := file.Save(rules); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("invalid dotenv content was saved or leaked in error")
	}
	data, _ := os.ReadFile(path)
	if string(data) != broken {
		t.Fatal("failed save changed .env")
	}
	link := filepath.Join(t.TempDir(), ".env")
	os.Symlink(path, link)
	file.Path = link
	if err := file.Save(rules); err == nil {
		t.Fatal("save followed a symlink")
	}
}
