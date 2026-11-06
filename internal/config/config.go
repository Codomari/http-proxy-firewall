package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Load merges YAML defaults and overrides, then process environment and flags.
// ExportEnvironment is called once by main after complete validation succeeds.
func Load(args []string, output io.Writer) (Config, error) {
	store := NewYAMLStore(DefaultYAML, OverrideYAML)
	document, err := store.Read()
	if err != nil {
		return Config{}, err
	}
	values := make(map[string]string)
	if err := mergeDeploymentValues(values, document.Environment()); err != nil {
		return Config{}, err
	}
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		environment[key] = value
	}
	if err := mergeDeploymentValues(values, environment); err != nil {
		return Config{}, err
	}
	parsed, err := Parse(args, values, output)
	if err != nil {
		return Config{}, err
	}
	parsed.Source, parsed.environment = store, document.Environment()
	return parsed, nil
}

func (c Config) ExportEnvironment() error {
	if c.Source == nil {
		return nil
	}
	return c.Source.Export(c.environment)
}

func Parse(args []string, values map[string]string, output io.Writer) (Config, error) {
	c, err := fromEnvironment(values)
	if err != nil {
		return Config{}, err
	}
	c, err = parseFlags(c, args, output)
	if err != nil {
		return Config{}, err
	}
	if !strings.Contains(c.Proxy.Upstream, "://") {
		c.Proxy.Upstream = "http://" + c.Proxy.Upstream
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func fromEnvironment(values map[string]string) (Config, error) {
	c := Defaults()
	r := environment{values: values}
	r.applyHTTP(&c.HTTP)
	r.applyProxy(&c.Proxy)
	r.applyTLS(&c.TLS)
	r.applyFirewall(&c.Firewall)
	r.applyRedis(&c.Redis)
	r.applyIntelligence(&c.Intelligence)
	r.applyObservability(&c.Observability)
	r.applyAdmin(&c.Admin)
	return c, errors.Join(r.errs...)
}

func (r *environment) applyHTTP(settings *HTTP) {
	settings.Listen = r.text("PF_LISTEN", settings.Listen)
	settings.TLSListen = r.text("PF_TLS_LISTEN", settings.TLSListen)
	settings.ReadTimeout = r.duration("PF_READ_TIMEOUT", settings.ReadTimeout)
	settings.WriteTimeout = r.duration("PF_WRITE_TIMEOUT", settings.WriteTimeout)
	settings.IdleTimeout = r.duration("PF_IDLE_TIMEOUT", settings.IdleTimeout)
	settings.MaxConnections = r.integer("PF_MAX_CONNECTIONS", settings.MaxConnections)
	settings.MaxConcurrentRequests = r.integer("PF_MAX_CONCURRENT_REQUESTS", settings.MaxConcurrentRequests)
}

func (r *environment) applyProxy(settings *Proxy) {
	settings.Upstream = r.text("PF_PROXY_TO", settings.Upstream)
	settings.Routes = parseRoutes(r.text("PF_UPSTREAM_ROUTES", ""), &r.errs)
	settings.MaxConnections = r.integer("PF_UPSTREAM_MAX_CONNECTIONS", settings.MaxConnections)
	settings.AllowOverflow = r.boolean("PF_UPSTREAM_ALLOW_OVERFLOW", settings.AllowOverflow)
	settings.MaxOverflowConnections = r.integer("PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS", settings.MaxOverflowConnections)
	settings.RequestRetryTimes = r.integer("PF_UPSTREAM_REQUEST_RETRY_TIMES", settings.RequestRetryTimes)
	settings.ReadTimeout = r.duration("PF_UPSTREAM_READ_TIMEOUT", settings.ReadTimeout)
	settings.WriteTimeout = r.duration("PF_UPSTREAM_WRITE_TIMEOUT", settings.WriteTimeout)
	settings.IdleTimeout = r.duration("PF_UPSTREAM_IDLE_TIMEOUT", settings.IdleTimeout)
	if v, ok := r.values["PF_IPV4_REDIRECT"]; ok {
		settings.IPv4Redirect = v
	}
}

func (r *environment) applyTLS(settings *TLS) {
	settings.Enabled = r.boolean("PF_TLS_ENABLED", settings.Enabled)
	settings.Email = r.text("LETSENCRYPT_EMAIL", "")
	settings.CacheDir = r.text("PF_TLS_CACHE_DIR", settings.CacheDir)
	settings.Hosts = r.csv("PF_TLS_HOSTS")
	settings.AllowLegacyClients = r.boolean("PF_TLS_ALLOW_LEGACY", false)
	settings.CertificateFile = r.text("PF_TLS_CERT_FILE", "")
	settings.PrivateKeyFile = r.text("PF_TLS_KEY_FILE", "")
}

func (r *environment) applyFirewall(settings *Firewall) {
	settings.MaxBodyBytes = r.int64("CVE_MITIGATOR_MAX_BODY_BYTES", settings.MaxBodyBytes)
	settings.MaxBufferedBytes = r.int64("PF_MAX_BUFFERED_BYTES", settings.MaxBufferedBytes)
	settings.WhitelistIPs = r.csv("IP_FILTER_WHITELIST")
	settings.WhitelistNetworks = append(settings.WhitelistNetworks, r.csv("IP_FILTER_WHITELIST_NETWORKS")...)
	settings.AllowedCountries = r.csv("IP_FILTER_ALLOWED_COUNTRIES")
	settings.WhitelistCheckpoint = r.boolean("IP_FILTER_WHITELIST_CHECKPOINT", settings.WhitelistCheckpoint)
	settings.CountryCheckpoint = r.boolean("IP_FILTER_COUNTRIES_CHECKPOINT", settings.CountryCheckpoint)
	settings.TrustedProxies = r.csv("PF_TRUSTED_PROXIES")
	settings.TrustCloudflareHeader = r.boolean("PF_TRUST_CLOUDFLARE_HEADER", false)
	settings.CloudflareHostsFile = r.text("PF_CLOUDFLARE_HOSTS_FILE", settings.CloudflareHostsFile)
	threshold := r.int64("DOS_DETECTOR_HOSTNAME_REQUEST_THRESHOLD", int64(settings.RequestThreshold))
	if threshold <= 0 {
		r.errs = append(r.errs, errors.New("DOS_DETECTOR_HOSTNAME_REQUEST_THRESHOLD must be positive"))
	} else {
		settings.RequestThreshold = uint64(threshold)
	}
	settings.PenaltyLifetime = r.duration("DOS_DETECTOR_HOSTNAME_PENALTY_LIFETIME", settings.PenaltyLifetime)
	settings.CookieLifetime = r.duration("PF_COOKIE_LIFETIME", settings.CookieLifetime)
	settings.CacheCapacity = r.integer("PF_CACHE_CAPACITY", settings.CacheCapacity)
	settings.UploadProgressNames = r.csv("CVE_MITIGATOR_UPLOAD_PROGRESS_NAMES")
	settings.RejectionLogInterval = r.duration("PF_REJECTION_LOG_INTERVAL", settings.RejectionLogInterval)
}

func (r *environment) applyRedis(settings *Redis) {
	settings.Enabled = r.boolean("PF_ENABLE_REDIS", false)
	settings.Address = r.text("REDIS_ADDRESS", settings.Address)
	settings.Password = r.text("REDIS_PASSWORD", "")
	settings.DB = r.integer("REDIS_DB", 0)
	settings.Timeout = r.duration("REDIS_TIMEOUT", settings.Timeout)
	settings.QueueSize = r.integer("REDIS_QUEUE_SIZE", settings.QueueSize)
	settings.Workers = r.integer("REDIS_WORKERS", settings.Workers)
}

func (r *environment) applyIntelligence(settings *Intelligence) {
	settings.DatabasePath = r.text("MAXMIND_DATABASE_PATH", settings.DatabasePath)
	settings.MaxMindLicenseKey = r.text("MAXMIND_LICENSE_KEY", "")
	if value, ok := r.values["PF_GOOGLE_RANGES_URL"]; ok {
		settings.GoogleRangesURL = strings.TrimSpace(value)
	}
	settings.RefreshInterval = r.duration("PF_INTELLIGENCE_REFRESH_INTERVAL", settings.RefreshInterval)
	settings.HTTPTimeout = r.duration("PF_INTELLIGENCE_HTTP_TIMEOUT", settings.HTTPTimeout)
}

func (r *environment) applyObservability(settings *Observability) {
	settings.Metrics = r.boolean("PF_METRICS", false)
	if v, ok := r.values["PF_PPROF_ADDRESS"]; ok {
		settings.PprofAddress = v
	}
	settings.Silent = r.boolean("PF_SILENT", true)
}

func (r *environment) applyAdmin(settings *Admin) {
	if uri, ok := r.values["PF_ADMIN_URI"]; ok {
		settings.URI = uri
	}
	settings.CredentialsFile = r.text("PF_ADMIN_CREDS_FILE", "")
	settings.Enabled = r.boolean("PF_ADMIN_ENABLED", settings.CredentialsFile != "")
	settings.MaxHosts = r.integer("PF_ADMIN_MAX_HOSTS", settings.MaxHosts)
	if settings.CredentialsFile != "" {
		accounts, err := readAdminCredentials(settings.CredentialsFile)
		if err != nil {
			r.errs = append(r.errs, err)
			return
		}
		settings.Accounts = accounts
	}
}

func parseFlags(c Config, args []string, output io.Writer) (Config, error) {
	flags := flag.NewFlagSet("proxy-firewall", flag.ContinueOnError)
	if output == nil {
		output = io.Discard
	}
	flags.SetOutput(output)
	flags.StringVar(&c.HTTP.Listen, "listen", c.HTTP.Listen, "HTTP listen address")
	flags.StringVar(&c.HTTP.TLSListen, "tls-listen", c.HTTP.TLSListen, "HTTPS listen address")
	flags.StringVar(&c.Proxy.Upstream, "proxy-to", c.Proxy.Upstream, "upstream HTTP(S) address")
	flags.Func("upstream-routes", "comma-separated hostname=HTTP(S)-origin routes", func(value string) error {
		var errs []error
		c.Proxy.Routes = parseRoutes(value, &errs)
		return errors.Join(errs...)
	})
	flags.BoolVar(&c.Observability.Metrics, "metrics", c.Observability.Metrics, "enable Prometheus endpoint")
	flags.BoolVar(&c.Observability.Silent, "silent", c.Observability.Silent, "log warnings and errors only")
	flags.BoolVar(&c.Redis.Enabled, "enable-redis", c.Redis.Enabled, "enable optional Redis cache")
	flags.StringVar(&c.Observability.PprofAddress, "pprof-addr", c.Observability.PprofAddress, "pprof address; empty disables")
	flags.BoolVar(&c.TLS.Enabled, "tls", c.TLS.Enabled, "enable automatic HTTPS")
	flags.StringVar(&c.TLS.CertificateFile, "tls-cert", c.TLS.CertificateFile, "static TLS certificate PEM file")
	flags.StringVar(&c.TLS.PrivateKeyFile, "tls-key", c.TLS.PrivateKeyFile, "static TLS private key PEM file")
	flags.BoolVar(&c.TLS.AllowLegacyClients, "tls-legacy", c.TLS.AllowLegacyClients, "allow TLS 1.0/1.1 clients")
	flags.Func("tls-hosts", "comma-separated certificate host allowlist", func(v string) error { c.TLS.Hosts = split(v); return nil })
	flags.StringVar(&c.Proxy.IPv4Redirect, "ipv4-redirect", c.Proxy.IPv4Redirect, "redirect IPv4 Host requests; empty disables")
	flags.Int64Var(&c.Firewall.MaxBodyBytes, "max-body-bytes", c.Firewall.MaxBodyBytes, "maximum inspected request body")
	flags.Int64Var(&c.Firewall.MaxBufferedBytes, "max-buffered-bytes", c.Firewall.MaxBufferedBytes, "global inspection buffer budget")
	flags.IntVar(&c.HTTP.MaxConnections, "max-connections", c.HTTP.MaxConnections, "maximum inbound connections")
	flags.IntVar(&c.HTTP.MaxConcurrentRequests, "max-concurrent-requests", c.HTTP.MaxConcurrentRequests, "maximum active request handlers")
	flags.IntVar(&c.Proxy.MaxConnections, "upstream-max-connections", c.Proxy.MaxConnections, "maximum upstream connections")
	flags.BoolVar(&c.Proxy.AllowOverflow, "upstream-allow-overflow", c.Proxy.AllowOverflow, "allow temporary upstream burst connections")
	flags.IntVar(&c.Proxy.MaxOverflowConnections, "upstream-max-overflow-connections", c.Proxy.MaxOverflowConnections, "absolute upstream connection ceiling when overflow is enabled")
	flags.IntVar(&c.Proxy.RequestRetryTimes, "upstream-request-retry-times", c.Proxy.RequestRetryTimes, "additional retries for safe upstream connection failures (0 disables)")
	flags.DurationVar(&c.HTTP.ReadTimeout, "read-timeout", c.HTTP.ReadTimeout, "inbound request read deadline")
	flags.DurationVar(&c.HTTP.WriteTimeout, "write-timeout", c.HTTP.WriteTimeout, "inbound response write deadline")
	flags.DurationVar(&c.Proxy.ReadTimeout, "upstream-read-timeout", c.Proxy.ReadTimeout, "upstream response read deadline")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected positional arguments")
	}
	return c, nil
}

func (c Config) Validate() error {
	var errs []error
	check := func(ok bool, message string) {
		if !ok {
			errs = append(errs, errors.New(message))
		}
	}
	_, adminPathErr := AdminPath(c.Admin.URI)
	check(adminPathErr == nil, "PF_ADMIN_URI must be a non-root path using letters, numbers, slash, dot, underscore, hyphen or tilde")
	_, _, err := net.SplitHostPort(c.HTTP.Listen)
	check(err == nil, "listen must be host:port")
	if c.TLS.Enabled {
		_, _, err = net.SplitHostPort(c.HTTP.TLSListen)
		check(err == nil, "tls-listen must be host:port")
	}
	check((c.TLS.CertificateFile == "") == (c.TLS.PrivateKeyFile == ""), "TLS certificate and key must be supplied together")
	u, err := url.Parse(c.Proxy.Upstream)
	check(err == nil && u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/"), "proxy-to must be an HTTP(S) origin without credentials, path or query")
	for hostname, target := range c.Proxy.Routes {
		check(hostname != "" && !strings.ContainsAny(hostname, " /\\:*[]"), "upstream route keys must be DNS hostnames without ports")
		origin, err := url.Parse(target)
		check(err == nil && origin != nil && (origin.Scheme == "http" || origin.Scheme == "https") && origin.Hostname() != "" && origin.User == nil && origin.RawQuery == "" && origin.Fragment == "" && (origin.Path == "" || origin.Path == "/"), "upstream routes must use HTTP(S) origins without credentials, paths or queries")
	}
	if c.Proxy.IPv4Redirect != "" {
		u, err = url.Parse(c.Proxy.IPv4Redirect)
		check(err == nil && u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil, "ipv4-redirect must be an absolute HTTP(S) URL")
	}
	check(c.Firewall.MaxBodyBytes > 0 && c.Firewall.MaxBodyBytes < int64(math.MaxInt), "max-body-bytes must fit a positive int with room for overflow probe")
	check(c.Firewall.MaxBufferedBytes > c.Firewall.MaxBodyBytes, "max-buffered-bytes must exceed max-body-bytes")
	check(c.Firewall.CacheCapacity > 0, "cache capacity must be positive")
	check(!c.Admin.Enabled || len(c.Admin.Accounts) > 0, "admin requires a PF_ADMIN_CREDS_FILE containing user:password accounts")
	users := make(map[string]struct{}, len(c.Admin.Accounts))
	for _, account := range c.Admin.Accounts {
		check(account.User != "" && account.Password != "", "admin accounts require both user and password")
		check(!strings.ContainsAny(account.User, ":\r\n\x00") && !strings.ContainsAny(account.Password, "\r\n\x00"), "admin credentials contain unsupported characters")
		check(len(account.User)+len(account.Password)+1 <= 3000, "admin credentials exceed the authentication header limit")
		_, duplicate := users[account.User]
		check(!duplicate, "admin account usernames must be unique")
		users[account.User] = struct{}{}
	}
	check(c.Admin.MaxHosts > 0 && c.Admin.MaxHosts <= 1000000, "PF_ADMIN_MAX_HOSTS must be between 1 and 1000000")
	check(c.Firewall.RequestThreshold > 0, "request threshold must be positive")
	check(c.Firewall.RejectionLogInterval >= 0, "rejection log interval cannot be negative")
	check(c.HTTP.MaxConnections > 0 && c.HTTP.MaxConcurrentRequests > 0 && c.Proxy.MaxConnections > 0, "connection and concurrency limits must be positive")
	check(c.Proxy.RequestRetryTimes >= 0, "PF_UPSTREAM_REQUEST_RETRY_TIMES must be a non-negative integer")
	if err := ConnectionLimitsFromConfig(c).Validate(); err != nil {
		errs = append(errs, err)
	}
	check(c.HTTP.ReadTimeout > 0 && c.HTTP.WriteTimeout > 0 && c.HTTP.IdleTimeout > 0 && c.Proxy.ReadTimeout > 0 && c.Proxy.WriteTimeout > 0 && c.Proxy.IdleTimeout > 0, "HTTP timeouts must be positive")
	check(c.Firewall.SamplingWindow >= time.Second && c.Firewall.PenaltyLifetime > 0 && c.Firewall.CookieLifetime > 0, "firewall durations must be positive and sampling window at least one second")
	check(c.Redis.DB >= 0 && c.Redis.Timeout > 0 && c.Redis.QueueSize > 0 && c.Redis.Workers > 0, "Redis database, timeout, queue size or worker count is invalid")
	check(c.Intelligence.RefreshInterval > 0 && c.Intelligence.HTTPTimeout > 0 && c.Intelligence.DatabasePath != "", "intelligence paths and durations must be configured")
	for _, prefix := range append(append([]string{}, c.Firewall.WhitelistNetworks...), c.Firewall.TrustedProxies...) {
		_, err := netip.ParsePrefix(prefix)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid network %q", prefix))
		}
	}
	for _, address := range c.Firewall.WhitelistIPs {
		if _, err := netip.ParseAddr(address); err != nil {
			errs = append(errs, fmt.Errorf("invalid whitelist IP %q", address))
		}
	}
	for _, host := range c.TLS.Hosts {
		check(host != "" && !strings.ContainsAny(host, " /\\:*[]") && !isIP(host), "TLS hosts must be DNS names")
	}
	return errors.Join(errs...)
}

func isIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

func parseRoutes(value string, errs *[]error) map[string]string {
	routes := make(map[string]string)
	for _, entry := range split(value) {
		hostname, origin, ok := strings.Cut(entry, "=")
		hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
		origin = strings.TrimSpace(origin)
		if !ok || hostname == "" || origin == "" {
			*errs = append(*errs, errors.New("upstream routes must use hostname=origin entries"))
			continue
		}
		if _, exists := routes[hostname]; exists {
			*errs = append(*errs, errors.New("duplicate upstream route hostname"))
			continue
		}
		if !strings.Contains(origin, "://") {
			origin = "http://" + origin
		}
		routes[hostname] = origin
	}
	return routes
}

type environment struct {
	values map[string]string
	errs   []error
}

func (e *environment) text(key, fallback string) string {
	if v := strings.TrimSpace(e.values[key]); v != "" {
		return v
	}
	return fallback
}
func (e *environment) csv(key string) []string { return split(e.values[key]) }
func split(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
func (e *environment) boolean(key string, fallback bool) bool {
	if v := e.text(key, ""); v != "" {
		result, err := strconv.ParseBool(v)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s must be a boolean", key))
			return fallback
		}
		return result
	}
	return fallback
}
func (e *environment) integer(key string, fallback int) int {
	if v := e.text(key, ""); v != "" {
		result, err := strconv.Atoi(v)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s must be an integer", key))
			return fallback
		}
		return result
	}
	return fallback
}
func (e *environment) int64(key string, fallback int64) int64 {
	if v := e.text(key, ""); v != "" {
		result, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s must be an integer", key))
			return fallback
		}
		return result
	}
	return fallback
}
func (e *environment) duration(key string, fallback time.Duration) time.Duration {
	if v := e.text(key, ""); v != "" {
		result, err := time.ParseDuration(v)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s must be a duration", key))
			return fallback
		}
		return result
	}
	return fallback
}
