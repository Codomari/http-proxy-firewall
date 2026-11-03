package config

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

const DefaultYAML = "proxy-firewall.default.yaml"
const OverrideYAML = "proxy-firewall.override.yaml"
const BehindCloudFlare = "Behind CloudFlare"

type EnvEntry struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// Presence enables this rule. False/null values remove a default-file entry
// from the effective configuration; administrators never need a boolean input.
type RuleParam struct {
	Key   string `yaml:"key"`
	Value *bool  `yaml:"value"`
}

type Rule struct {
	Type   string      `yaml:"type"`
	Params []RuleParam `yaml:"params"`
}

type DebugCapture struct {
	Host    string  `yaml:"host"`
	Source  string  `yaml:"source,omitempty"`
	Enabled *bool   `yaml:"enabled,omitempty"`
	LogFile *string `yaml:"log_file,omitempty"`
}

type Document struct {
	Env   []EnvEntry     `yaml:"env"`
	Rules []Rule         `yaml:"rules"`
	Debug []DebugCapture `yaml:"debug"`
}

type YAMLStore struct {
	DefaultPath  string
	OverridePath string
	mu           sync.Mutex
	external     map[string]bool
	exportLive   bool
}

func NewYAMLStore(defaultPath, overridePath string) *YAMLStore {
	external := make(map[string]bool)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		external[key] = true
	}
	return &YAMLStore{DefaultPath: defaultPath, OverridePath: overridePath, external: external}
}

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func debugIdentity(capture DebugCapture) string {
	if address, err := netip.ParseAddr(capture.Source); err == nil {
		capture.Source = address.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(capture.Host), ".")) + "\n" + capture.Source
}

func decodeDocument(data []byte) (Document, *yaml.Node, error) {
	var document Document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil && err != io.EOF {
		return Document{}, nil, errors.New("invalid configuration YAML; check fields, scalar values and duplicate keys")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Document{}, nil, errors.New("configuration must contain one YAML document")
	}
	keys := make(map[string]bool)
	for _, entry := range document.Env {
		if !envKey.MatchString(entry.Key) || keys[entry.Key] || strings.ContainsRune(entry.Value, 0) {
			return Document{}, nil, errors.New("env entries require unique valid environment keys and scalar values")
		}
		keys[entry.Key] = true
	}
	types := make(map[string]bool)
	for _, rule := range document.Rules {
		if rule.Type != BehindCloudFlare || types[rule.Type] {
			return Document{}, nil, errors.New("rules require unique supported types: Behind CloudFlare")
		}
		types[rule.Type] = true
		params := make(map[string]bool)
		for _, param := range rule.Params {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(param.Key), "."))
			if name == "" || params[name] {
				return Document{}, nil, errors.New("rule parameters require unique hostname keys")
			}
			params[name] = true
		}
	}
	identities := make(map[string]bool)
	for i := range document.Debug {
		capture := &document.Debug[i]
		if capture.Source != "" {
			address, err := netip.ParseAddr(capture.Source)
			if err != nil || address.Zone() != "" {
				return Document{}, nil, errors.New("debug source must be one IPv4/IPv6 address or blank")
			}
			capture.Source = address.Unmap().String()
		}
		identity := debugIdentity(*capture)
		if strings.TrimSpace(capture.Host) == "" || identities[identity] {
			return Document{}, nil, errors.New("debug entries require unique host/source combinations")
		}
		identities[identity] = true
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return Document{}, nil, errors.New("invalid configuration YAML")
	}
	if len(node.Content) == 0 {
		node = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if node.Content[0].Kind != yaml.MappingNode {
		return Document{}, nil, errors.New("configuration root must be a mapping")
	}
	return document, &node, nil
}

func readYAML(path string) (Document, *yaml.Node, []byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		doc, node, err := decodeDocument(nil)
		return doc, node, nil, nil, err
	}
	if err != nil || !info.Mode().IsRegular() {
		return Document{}, nil, nil, nil, errors.New("configuration must be an accessible regular YAML file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Document{}, nil, nil, nil, errors.New("cannot open configuration YAML")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return Document{}, nil, nil, nil, errors.New("configuration changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return Document{}, nil, nil, nil, errors.New("configuration exceeds the 1 MiB read limit")
	}
	doc, node, err := decodeDocument(data)
	return doc, node, data, info, err
}

func mergeDocuments(base, override Document) Document {
	result := Document{Env: append([]EnvEntry{}, base.Env...), Rules: []Rule{}, Debug: append([]DebugCapture{}, base.Debug...)}
	indices := make(map[string]int)
	for i, entry := range result.Env {
		indices[entry.Key] = i
	}
	for _, entry := range override.Env {
		if i, exists := indices[entry.Key]; exists {
			result.Env[i] = entry
		} else {
			indices[entry.Key] = len(result.Env)
			result.Env = append(result.Env, entry)
		}
	}
	params := make(map[string]*bool)
	order := []string{}
	for _, document := range []Document{base, override} {
		for _, rule := range document.Rules {
			for _, param := range rule.Params {
				name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(param.Key), "."))
				if _, exists := params[name]; !exists {
					order = append(order, name)
				}
				params[name] = param.Value
			}
		}
	}
	rule := Rule{Type: BehindCloudFlare, Params: []RuleParam{}}
	for _, name := range order {
		if value := params[name]; value != nil && *value {
			rule.Params = append(rule.Params, RuleParam{Key: name, Value: value})
		}
	}
	if len(rule.Params) > 0 {
		result.Rules = append(result.Rules, rule)
	}
	indices = make(map[string]int)
	for i, capture := range result.Debug {
		indices[debugIdentity(capture)] = i
	}
	for _, capture := range override.Debug {
		identity := debugIdentity(capture)
		if i, exists := indices[identity]; exists {
			if capture.Enabled != nil {
				result.Debug[i].Enabled = capture.Enabled
			}
			if capture.LogFile != nil {
				result.Debug[i].LogFile = capture.LogFile
			}
		} else {
			indices[identity] = len(result.Debug)
			result.Debug = append(result.Debug, capture)
		}
	}
	return result
}

func (document Document) Environment() map[string]string {
	values := make(map[string]string, len(document.Env))
	for _, entry := range document.Env {
		values[entry.Key] = entry.Value
	}
	return values
}

func (store *YAMLStore) Read() (Document, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	base, _, _, _, err := readYAML(store.DefaultPath)
	if err != nil {
		return Document{}, err
	}
	override, _, _, _, err := readYAML(store.OverridePath)
	if err != nil {
		return Document{}, err
	}
	return mergeDocuments(base, override), nil
}

func (store *YAMLStore) ProcessOverrides(keys []string) []string {
	result := []string{}
	for _, key := range keys {
		if store.external[key] {
			result = append(result, key)
		}
	}
	return result
}

func (store *YAMLStore) Export(values map[string]string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, value := range values {
		if !store.external[key] {
			if err := os.Setenv(key, value); err != nil {
				return errors.New("cannot export YAML environment")
			}
		}
	}
	store.exportLive = true
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func setMappingValue(node *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			old := node.Content[i+1]
			if value.HeadComment == "" {
				value.HeadComment = old.HeadComment
			}
			if value.LineComment == "" {
				value.LineComment = old.LineComment
			}
			if value.FootComment == "" {
				value.FootComment = old.FootComment
			}
			node.Content[i+1] = value
			return
		}
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func encodedNode(value any) *yaml.Node {
	var node yaml.Node
	_ = node.Encode(value)
	return &node
}

func keyedSequenceEntry(sequence *yaml.Node, field, key string) *yaml.Node {
	for _, entry := range sequence.Content {
		if value := mappingValue(entry, field); value != nil && value.Value == key {
			return entry
		}
	}
	return nil
}

func sectionSequence(root *yaml.Node, name string) *yaml.Node {
	section := mappingValue(root, name)
	if section == nil || section.Kind != yaml.SequenceNode {
		section = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setMappingValue(root, name, section)
	}
	return section
}

func (store *YAMLStore) update(mutator func(*yaml.Node) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, node, before, info, err := readYAML(store.OverridePath)
	if err != nil {
		return err
	}
	if err := mutator(node.Content[0]); err != nil {
		return err
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return errors.New("cannot encode override YAML")
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	if output.Len() > 1<<20 {
		return errors.New("override YAML exceeds the 1 MiB limit")
	}
	if _, _, err := decodeDocument(output.Bytes()); err != nil {
		return err
	}
	return writePrivateYAML(store.OverridePath, output.Bytes(), before, info)
}

func writePrivateYAML(path string, data, before []byte, info os.FileInfo) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".proxy-firewall.override-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	mode := os.FileMode(0600)
	if info != nil {
		mode = info.Mode().Perm()
	}
	modeErr := temp.Chmod(mode)
	_, writeErr := temp.Write(data)
	syncErr := temp.Sync()
	if err := errors.Join(modeErr, writeErr, syncErr, temp.Close()); err != nil {
		return err
	}
	_, _, current, currentInfo, err := readYAML(path)
	if err != nil || !bytes.Equal(before, current) || (info == nil) != (currentInfo == nil) || info != nil && !os.SameFile(info, currentInfo) {
		return errors.New("override YAML changed while saving; reload and retry")
	}
	return os.Rename(temp.Name(), path)
}

func (store *YAMLStore) UpdateEnvironment(values map[string]string) error {
	err := store.update(func(root *yaml.Node) error {
		section := sectionSequence(root, "env")
		for _, key := range generalRuleKeys {
			value, exists := values[key]
			if !exists {
				continue
			}
			entry := keyedSequenceEntry(section, "key", key)
			if entry == nil {
				section.Content = append(section.Content, encodedNode(EnvEntry{Key: key, Value: value}))
			} else {
				setMappingValue(entry, "value", encodedNode(value))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	store.mu.Lock()
	exportLive := store.exportLive
	store.mu.Unlock()
	if exportLive {
		return store.Export(values)
	}
	return nil
}

func (store *YAMLStore) SetCloudflareHost(host string, enabled bool) error {
	return store.update(func(root *yaml.Node) error {
		section := sectionSequence(root, "rules")
		rule := keyedSequenceEntry(section, "type", BehindCloudFlare)
		if rule == nil {
			rule = encodedNode(Rule{Type: BehindCloudFlare, Params: []RuleParam{}})
			section.Content = append(section.Content, rule)
		}
		params := sectionSequence(rule, "params")
		var entry *yaml.Node
		for _, candidate := range params.Content {
			if key := mappingValue(candidate, "key"); key != nil && strings.EqualFold(strings.TrimSuffix(key.Value, "."), host) {
				entry = candidate
				break
			}
		}
		if entry == nil {
			params.Content = append(params.Content, encodedNode(RuleParam{Key: host, Value: &enabled}))
		} else {
			setMappingValue(entry, "value", encodedNode(enabled))
		}
		return nil
	})
}

func (store *YAMLStore) SetDebug(capture DebugCapture) error {
	if capture.Enabled == nil {
		return errors.New("debug enabled must be specified")
	}
	return store.update(func(root *yaml.Node) error {
		section := sectionSequence(root, "debug")
		for _, entry := range section.Content {
			var old DebugCapture
			if err := entry.Decode(&old); err != nil {
				return errors.New("invalid debug configuration")
			}
			if debugIdentity(old) == debugIdentity(capture) {
				setMappingValue(entry, "enabled", encodedNode(*capture.Enabled))
				if capture.LogFile != nil {
					setMappingValue(entry, "log_file", encodedNode(*capture.LogFile))
				}
				return nil
			}
		}
		section.Content = append(section.Content, encodedNode(capture))
		return nil
	})
}
