package config

import (
	"errors"
	"math"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"http-proxy-firewall/internal/ipfirewall"
)

type GeneralRules struct {
	ConnectionLimits
	MaxBodyBytes              int64    `json:"max_body_bytes"`
	MaxBufferedBytes          int64    `json:"max_buffered_bytes"`
	HTTP2Enable               bool     `json:"http2_enable"`
	IdleRequestTimeout        string   `json:"idle_request_timeout"`
	GCPercent                 int      `json:"gc_percent"`
	GCMemoryLimit             string   `json:"gc_memory_limit"`
	WhitelistIPs              []string `json:"whitelist_ips"`
	WhitelistNetworks         []string `json:"whitelist_networks"`
	IPFirewallProviders       []string `json:"ip_firewall_providers"`
	IPFirewallNetworks        []string `json:"ip_firewall_networks"`
	AllowedCountries          []string `json:"allowed_countries"`
	IPCheckpoint              bool     `json:"ip_checkpoint"`
	CountryCheckpoint         bool     `json:"country_checkpoint"`
	DDoSThreshold             uint64   `json:"ddos_threshold"`
	UpstreamRequestRetryTimes int      `json:"upstream_request_retry_times"`
}

var generalRuleKeys = []string{"IP_FILTER_WHITELIST", "IP_FILTER_WHITELIST_NETWORKS", "IP_FILTER_ALLOWED_COUNTRIES", "IP_FILTER_WHITELIST_CHECKPOINT", "IP_FILTER_COUNTRIES_CHECKPOINT", "DOS_DETECTOR_HOSTNAME_REQUEST_THRESHOLD", "PF_UPSTREAM_REQUEST_RETRY_TIMES", "PF_MAX_CONCURRENT_REQUESTS", "PF_UPSTREAM_MAX_CONNECTIONS", "PF_UPSTREAM_ALLOW_OVERFLOW", "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS", "CVE_MITIGATOR_MAX_BODY_BYTES", "GOGC", "GOMEMLIMIT", "PF_MAX_BUFFERED_BYTES", "PF_HTTP2_ENABLE", "PF_IDLE_REQUEST_TIMEOUT", "PF_IDLE_TIMEOUT", "PF_IP_FIREWALL_PROVIDERS", "PF_IP_FIREWALL_NETWORKS"}

func GeneralRulesFromFirewall(f Firewall) GeneralRules {
	return GeneralRules{ConnectionLimits: ConnectionLimitsFromConfig(Defaults()), MaxBodyBytes: f.MaxBodyBytes, MaxBufferedBytes: f.MaxBufferedBytes, IdleRequestTimeout: Defaults().HTTP.IdleTimeout.String(), GCPercent: 100, GCMemoryLimit: "off", WhitelistIPs: f.WhitelistIPs, WhitelistNetworks: f.WhitelistNetworks, IPFirewallProviders: f.IPFirewallProviders, IPFirewallNetworks: f.IPFirewallNetworks, AllowedCountries: f.AllowedCountries, IPCheckpoint: f.WhitelistCheckpoint, CountryCheckpoint: f.CountryCheckpoint, DDoSThreshold: f.RequestThreshold}
}

func (rules GeneralRules) Normalize() (GeneralRules, error) {
	result := rules
	var settingsErr error
	result.IPFirewallProviders, result.IPFirewallNetworks, settingsErr = ipfirewall.NormalizeSettings(rules.IPFirewallProviders, rules.IPFirewallNetworks)
	if settingsErr != nil {
		return GeneralRules{}, settingsErr
	}
	if result.GCMemoryLimit == "" {
		result.GCMemoryLimit = "off"
	}
	if result.IdleRequestTimeout == "" {
		result.IdleRequestTimeout = Defaults().HTTP.IdleTimeout.String()
	}
	idleTimeout, err := time.ParseDuration(result.IdleRequestTimeout)
	if err != nil || idleTimeout <= 0 {
		return GeneralRules{}, errors.New("idle request timeout must be a positive duration such as 15s")
	}
	result.IdleRequestTimeout = idleTimeout.String()
	if _, err := RuntimeFromValues(map[string]string{"GOGC": gcPercentValue(result.GCPercent), "GOMEMLIMIT": result.GCMemoryLimit}); err != nil {
		return GeneralRules{}, err
	}
	if result.MaxBodyBytes <= 0 || result.MaxBodyBytes >= int64(math.MaxInt) {
		return GeneralRules{}, errors.New("maximum request body size must be a positive byte count with room for an overflow probe")
	}
	if result.MaxBufferedBytes <= result.MaxBodyBytes {
		return GeneralRules{}, errors.New("shared body buffer budget must be larger than the maximum request body size")
	}
	if err := result.ConnectionLimits.Validate(); err != nil {
		return GeneralRules{}, err
	}
	if result.UpstreamRequestRetryTimes < 0 {
		return GeneralRules{}, errors.New("upstream request retry times must be a non-negative integer")
	}
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

// GeneralRulesFile manages the general env entries in the YAML override.
// Unrelated configuration and secrets are never returned to the admin API.
type GeneralRulesFile struct {
	Path  string
	Store *YAMLStore
	mu    sync.Mutex
}

func (file *GeneralRulesFile) yamlStore() *YAMLStore {
	if file.Store != nil {
		return file.Store
	}
	return NewYAMLStore(filepath.Join(filepath.Dir(file.Path), DefaultYAML), file.Path)
}

func generalRulesFromValues(values map[string]string) (GeneralRules, error) {
	runtimeSettings, err := RuntimeFromValues(values)
	if err != nil {
		return GeneralRules{}, err
	}
	rules := GeneralRules{ConnectionLimits: ConnectionLimitsFromConfig(Defaults()), MaxBodyBytes: Defaults().Firewall.MaxBodyBytes, MaxBufferedBytes: Defaults().Firewall.MaxBufferedBytes, WhitelistIPs: split(values[generalRuleKeys[0]]), WhitelistNetworks: split(values[generalRuleKeys[1]]), AllowedCountries: split(values[generalRuleKeys[2]]), IPCheckpoint: true, CountryCheckpoint: true, DDoSThreshold: 200, UpstreamRequestRetryTimes: Defaults().Proxy.RequestRetryTimes}
	for key, target := range map[string]*int64{"CVE_MITIGATOR_MAX_BODY_BYTES": &rules.MaxBodyBytes, "PF_MAX_BUFFERED_BYTES": &rules.MaxBufferedBytes} {
		if value := values[key]; value != "" {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return GeneralRules{}, errors.New(key + " must be an integer")
			}
			*target = parsed
		}
	}
	rules.GCPercent = runtimeSettings.GCPercent
	rules.IPFirewallProviders = split(values["PF_IP_FIREWALL_PROVIDERS"])
	rules.IPFirewallNetworks = split(values["PF_IP_FIREWALL_NETWORKS"])
	rules.GCMemoryLimit = values["GOMEMLIMIT"]
	rules.IdleRequestTimeout = values["PF_IDLE_REQUEST_TIMEOUT"]
	if rules.IdleRequestTimeout == "" {
		rules.IdleRequestTimeout = values["PF_IDLE_TIMEOUT"]
	}
	if value := values["PF_HTTP2_ENABLE"]; value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return GeneralRules{}, errors.New("PF_HTTP2_ENABLE must be true or false")
		}
		rules.HTTP2Enable = parsed
	}
	for key, target := range map[string]*int{"PF_MAX_CONCURRENT_REQUESTS": &rules.MaxConcurrentRequests, "PF_UPSTREAM_MAX_CONNECTIONS": &rules.UpstreamMaxConnections, "PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": &rules.UpstreamMaxOverflowConnections} {
		if value := values[key]; value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return GeneralRules{}, errors.New(key + " must be an integer")
			}
			*target = parsed
		}
	}
	if value := values["PF_UPSTREAM_ALLOW_OVERFLOW"]; value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return GeneralRules{}, errors.New("PF_UPSTREAM_ALLOW_OVERFLOW must be true or false")
		}
		rules.UpstreamAllowOverflow = parsed
	}
	if value := values[generalRuleKeys[6]]; value != "" {
		var err error
		rules.UpstreamRequestRetryTimes, err = strconv.Atoi(value)
		if err != nil {
			return GeneralRules{}, errors.New("upstream request retry times must be a non-negative integer")
		}
	}
	if value := values[generalRuleKeys[5]]; value != "" {
		threshold, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return GeneralRules{}, errors.New("DDoS threshold must be a positive integer")
		}
		rules.DDoSThreshold = threshold
	}
	for i, target := range []*bool{&rules.IPCheckpoint, &rules.CountryCheckpoint} {
		if value := values[generalRuleKeys[3+i]]; value != "" {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return GeneralRules{}, errors.New("checkpoint settings must be true or false")
			}
			*target = parsed
		}
	}
	return rules.Normalize()
}

func (file *GeneralRulesFile) Read() (GeneralRules, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	document, err := file.yamlStore().Read()
	if err != nil {
		return GeneralRules{}, err
	}
	return generalRulesFromValues(document.Environment())
}

func (file *GeneralRulesFile) Save(rules GeneralRules) error {
	rules, err := rules.Normalize()
	if err != nil {
		return err
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	return file.yamlStore().UpdateEnvironment(map[string]string{
		generalRuleKeys[0]: strings.Join(rules.WhitelistIPs, ","), generalRuleKeys[1]: strings.Join(rules.WhitelistNetworks, ","), generalRuleKeys[2]: strings.Join(rules.AllowedCountries, ","),
		generalRuleKeys[3]: strconv.FormatBool(rules.IPCheckpoint), generalRuleKeys[4]: strconv.FormatBool(rules.CountryCheckpoint), generalRuleKeys[5]: strconv.FormatUint(rules.DDoSThreshold, 10),
		generalRuleKeys[6]:                     strconv.Itoa(rules.UpstreamRequestRetryTimes),
		"PF_MAX_CONCURRENT_REQUESTS":           strconv.Itoa(rules.MaxConcurrentRequests),
		"PF_UPSTREAM_MAX_CONNECTIONS":          strconv.Itoa(rules.UpstreamMaxConnections),
		"PF_UPSTREAM_ALLOW_OVERFLOW":           strconv.FormatBool(rules.UpstreamAllowOverflow),
		"PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS": strconv.Itoa(rules.UpstreamMaxOverflowConnections),
		"CVE_MITIGATOR_MAX_BODY_BYTES":         strconv.FormatInt(rules.MaxBodyBytes, 10),
		"PF_MAX_BUFFERED_BYTES":                strconv.FormatInt(rules.MaxBufferedBytes, 10),
		"PF_HTTP2_ENABLE":                      strconv.FormatBool(rules.HTTP2Enable),
		"PF_IDLE_REQUEST_TIMEOUT":              rules.IdleRequestTimeout,
		"GOGC":                                 gcPercentValue(rules.GCPercent),
		"GOMEMLIMIT":                           rules.GCMemoryLimit,
		"PF_IP_FIREWALL_PROVIDERS":             strings.Join(rules.IPFirewallProviders, ","),
		"PF_IP_FIREWALL_NETWORKS":              strings.Join(rules.IPFirewallNetworks, ","),
	})
}

func (file *GeneralRulesFile) ProcessOverrides() []string {
	return file.yamlStore().ProcessOverrides(generalRuleKeys)
}
