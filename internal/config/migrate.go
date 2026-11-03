package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/joho/godotenv"
	"go.yaml.in/yaml/v3"
)

// MigrateLegacy is the only dotenv reader. It verifies a private YAML copy
// before removing the old configuration; normal startup reads YAML only.
func MigrateLegacy(directory string) error {
	legacy := make(map[string][]byte)
	values := make(map[string]string)
	originalEnv := make(map[string]string)
	for _, name := range []string{".env", "proxy-firewall.conf"} {
		file, err := os.Open(filepath.Join(directory, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errors.New("cannot read legacy configuration")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 1<<20 {
			return errors.New("legacy configuration exceeds the 1 MiB limit")
		}
		entries, err := godotenv.Unmarshal(string(data))
		if err != nil {
			return errors.New("cannot parse legacy configuration; original files were retained")
		}
		if name == ".env" {
			originalEnv = entries
		}
		if err := mergeDeploymentValues(values, entries); err != nil {
			return errors.New("invalid legacy configuration values")
		}
		legacy[name] = data
	}
	if len(legacy) == 0 {
		return nil
	}
	store := NewYAMLStore(filepath.Join(directory, DefaultYAML), filepath.Join(directory, OverrideYAML))
	_, node, before, info, err := readYAML(store.OverridePath)
	if err != nil {
		return err
	}
	root := node.Content[0]
	env := sectionSequence(root, "env")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := keyedSequenceEntry(env, "key", key)
		if entry == nil {
			entry = encodedNode(EnvEntry{Key: key, Value: values[key]})
			env.Content = append(env.Content, entry)
		}
		if value, exists := originalEnv[key]; exists && value != values[key] {
			entry.HeadComment = "Original .env value (overridden by legacy deployment configuration): " + key + "=" + strconv.Quote(value)
		}
	}
	// Preserve every original .env key, including legacy aliases normalized
	// above. Effective canonical settings retain their old precedence.
	for key, value := range originalEnv {
		if keyedSequenceEntry(env, "key", key) == nil {
			env.Content = append(env.Content, encodedNode(EnvEntry{Key: key, Value: value}))
		}
	}
	if mappingValue(root, "rules") == nil {
		path := values["PF_CLOUDFLARE_HOSTS_FILE"]
		if path == "" {
			path = "files/cloudflare-hosts.json"
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(directory, path)
		}
		if data, err := os.ReadFile(path); err == nil {
			var hosts map[string]bool
			if len(data) > 128<<10 || json.Unmarshal(data, &hosts) != nil {
				return errors.New("cannot migrate legacy Cloudflare rules")
			}
			names := make([]string, 0, len(hosts))
			for host := range hosts {
				names = append(names, host)
			}
			sort.Strings(names)
			rule := Rule{Type: BehindCloudFlare, Params: []RuleParam{}}
			for _, host := range names {
				enabled := hosts[host]
				rule.Params = append(rule.Params, RuleParam{Key: host, Value: &enabled})
			}
			setMappingValue(root, "rules", encodedNode([]Rule{rule}))
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot read legacy Cloudflare rules")
		}
	}
	sectionSequence(root, "rules")
	sectionSequence(root, "debug")
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return errors.New("cannot encode migrated configuration")
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	if output.Len() > 1<<20 {
		return errors.New("migrated configuration exceeds the 1 MiB limit; original files were retained")
	}
	if _, _, err := decodeDocument(output.Bytes()); err != nil {
		return err
	}
	if err := writePrivateYAML(store.OverridePath, output.Bytes(), before, info); err != nil {
		return err
	}
	_, _, persisted, _, err := readYAML(store.OverridePath)
	if err != nil || !bytes.Equal(persisted, output.Bytes()) {
		return errors.New("cannot verify migrated YAML; original files were retained")
	}
	for name, expected := range legacy {
		current, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(current, expected) {
			return errors.New("legacy configuration changed during migration; original files were retained")
		}
	}
	for name := range legacy {
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			return errors.New("YAML saved, but a legacy configuration file could not be removed")
		}
	}
	return nil
}
