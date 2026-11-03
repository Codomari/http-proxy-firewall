package config

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/joho/godotenv"
)

type GeneralRules struct {
	WhitelistIPs      []string `json:"whitelist_ips"`
	WhitelistNetworks []string `json:"whitelist_networks"`
	AllowedCountries  []string `json:"allowed_countries"`
	IPCheckpoint      bool     `json:"ip_checkpoint"`
	CountryCheckpoint bool     `json:"country_checkpoint"`
	DDoSThreshold     uint64   `json:"ddos_threshold"`
}

var generalRuleKeys = []string{"IP_FILTER_WHITELIST", "IP_FILTER_WHITELIST_NETWORKS", "IP_FILTER_ALLOWED_COUNTRIES", "IP_FILTER_WHITELIST_CHECKPOINT", "IP_FILTER_COUNTRIES_CHECKPOINT", "DOS_DETECTOR_HOSTNAME_REQUEST_THRESHOLD"}

func GeneralRulesFromFirewall(f Firewall) GeneralRules {
	return GeneralRules{WhitelistIPs: f.WhitelistIPs, WhitelistNetworks: f.WhitelistNetworks, AllowedCountries: f.AllowedCountries, IPCheckpoint: f.WhitelistCheckpoint, CountryCheckpoint: f.CountryCheckpoint, DDoSThreshold: f.RequestThreshold}
}

func (rules GeneralRules) Normalize() (GeneralRules, error) {
	result := rules
	if result.DDoSThreshold < 1 || result.DDoSThreshold > 1_000_000_000 {
		return GeneralRules{}, errors.New("DDoS threshold must be between 1 and 1000000000 requests per second")
	}
	lists := []*[]string{&result.WhitelistIPs, &result.WhitelistNetworks, &result.AllowedCountries}
	for kind, list := range lists {
		if len(*list) > 512 {
			return GeneralRules{}, errors.New("each whitelist is limited to 512 entries")
		}
		normalized := []string{}
		seen := map[string]bool{}
		for _, raw := range *list {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			switch kind {
			case 0:
				ip, err := netip.ParseAddr(value)
				if err != nil || ip.Zone() != "" {
					return GeneralRules{}, errors.New("whitelisted IPs must be single IPv4 or IPv6 addresses")
				}
				value = ip.Unmap().String()
			case 1:
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					return GeneralRules{}, errors.New("whitelisted networks must use CIDR notation")
				}
				value = prefix.Masked().String()
			case 2:
				if len(value) > 96 {
					return GeneralRules{}, errors.New("country names must be at most 96 bytes")
				}
				for _, ch := range value {
					if !unicode.IsLetter(ch) && !unicode.IsMark(ch) && !strings.ContainsRune(" '-.()’", ch) {
						return GeneralRules{}, errors.New("use country names such as Azerbaijan or Turkey")
					}
				}
			}
			key := strings.ToLower(value)
			if !seen[key] {
				normalized = append(normalized, value)
				seen[key] = true
			}
		}
		*list = normalized
	}
	return result, nil
}

// GeneralRulesFile exposes only the managed whitelist settings. Other .env
// contents are never returned to the admin API or included in errors.
type GeneralRulesFile struct {
	Path string
	mu   sync.Mutex
}

func readGeneralRulesFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, errors.New(".env must be an accessible regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New(".env changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, nil, errors.New("unable to read .env within the 1 MiB limit")
	}
	return data, info, nil
}

func generalRulesFromData(data []byte) (GeneralRules, error) {
	values, err := godotenv.Unmarshal(string(data))
	if err != nil {
		return GeneralRules{}, errors.New(".env is not valid dotenv syntax")
	}
	rules := GeneralRules{WhitelistIPs: split(values[generalRuleKeys[0]]), WhitelistNetworks: split(values[generalRuleKeys[1]]), AllowedCountries: split(values[generalRuleKeys[2]]), IPCheckpoint: true, CountryCheckpoint: true, DDoSThreshold: 200}
	if value := values[generalRuleKeys[5]]; value != "" {
		threshold, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return GeneralRules{}, errors.New("DDoS threshold in .env must be a positive integer")
		}
		rules.DDoSThreshold = threshold
	}
	for i, target := range []*bool{&rules.IPCheckpoint, &rules.CountryCheckpoint} {
		if value := values[generalRuleKeys[3+i]]; value != "" {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return GeneralRules{}, errors.New("checkpoint settings in .env must be true or false")
			}
			*target = parsed
		}
	}
	return rules.Normalize()
}

func (file *GeneralRulesFile) Read() (GeneralRules, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	data, _, err := readGeneralRulesFile(file.Path)
	if err != nil {
		return GeneralRules{}, err
	}
	return generalRulesFromData(data)
}

// Edit only managed assignment values, preserving unrelated bytes, comments,
// multiline secrets, export prefixes, duplicate keys, and original line endings.
func updateGeneralRulesData(data []byte, rules GeneralRules) ([]byte, error) {
	updates := map[string]string{
		generalRuleKeys[0]: strings.Join(rules.WhitelistIPs, ","), generalRuleKeys[1]: strings.Join(rules.WhitelistNetworks, ","), generalRuleKeys[2]: strings.Join(rules.AllowedCountries, ","),
		generalRuleKeys[3]: strconv.FormatBool(rules.IPCheckpoint), generalRuleKeys[4]: strconv.FormatBool(rules.CountryCheckpoint),
		generalRuleKeys[5]: strconv.FormatUint(rules.DDoSThreshold, 10),
	}
	if _, err := godotenv.Unmarshal(string(data)); err != nil {
		return nil, errors.New(".env is not valid dotenv syntax")
	}
	var out bytes.Buffer
	seen := map[string]bool{}
	last := 0
	for pos := 0; pos < len(data); {
		for pos < len(data) && strings.ContainsRune(" \t\r\n", rune(data[pos])) {
			pos++
		}
		if pos >= len(data) {
			break
		}
		if data[pos] == '#' {
			if n := bytes.IndexByte(data[pos:], '\n'); n >= 0 {
				pos += n + 1
				continue
			}
			break
		}
		delimiter := bytes.IndexAny(data[pos:], "=:\n")
		if delimiter < 0 || data[pos+delimiter] == '\n' {
			return nil, errors.New("unsupported .env assignment")
		}
		key := strings.TrimSpace(string(data[pos : pos+delimiter]))
		if strings.HasPrefix(key, "export ") || strings.HasPrefix(key, "export\t") {
			key = strings.TrimSpace(key[len("export"):])
		}
		start := pos + delimiter + 1
		for start < len(data) && (data[start] == ' ' || data[start] == '\t') {
			start++
		}
		end := start
		if start < len(data) && (data[start] == '\'' || data[start] == '"') {
			quote := data[start]
			end++
			for end < len(data) && (data[end] != quote || data[end-1] == '\\') {
				end++
			}
			if end == len(data) {
				return nil, errors.New("unterminated .env value")
			}
			end++
			pos = end
		} else {
			for end < len(data) && data[end] != '\n' && data[end] != '\r' {
				end++
			}
			pos = end
			for i := start + 1; i < end; i++ {
				if data[i] == '#' && (data[i-1] == ' ' || data[i-1] == '\t') {
					end = i
					break
				}
			}
			for end > start && (data[end-1] == ' ' || data[end-1] == '\t') {
				end--
			}
		}
		if value, managed := updates[key]; managed {
			out.Write(data[last:start])
			out.WriteString(strconv.Quote(value))
			last = end
			seen[key] = true
		}
	}
	out.Write(data[last:])
	newline := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		newline = "\r\n"
	}
	for _, key := range generalRuleKeys {
		if !seen[key] {
			if out.Len() > 0 && out.Bytes()[out.Len()-1] != '\n' {
				out.WriteString(newline)
			}
			out.WriteString(key + "=" + strconv.Quote(updates[key]) + newline)
		}
	}
	if _, err := generalRulesFromData(out.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (file *GeneralRulesFile) Save(rules GeneralRules) error {
	rules, err := rules.Normalize()
	if err != nil {
		return err
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	before, info, err := readGeneralRulesFile(file.Path)
	if err != nil {
		return err
	}
	data, err := updateGeneralRulesData(before, rules)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(file.Path), ".env-settings-*")
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
	current, currentInfo, err := readGeneralRulesFile(file.Path)
	if err != nil || !bytes.Equal(before, current) || (info == nil) != (currentInfo == nil) || info != nil && !os.SameFile(info, currentInfo) {
		return errors.New(".env changed while saving; reload settings and retry")
	}
	return os.Rename(temp.Name(), file.Path)
}
