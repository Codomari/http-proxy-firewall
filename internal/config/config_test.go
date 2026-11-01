package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyFlagsOverrideEnvironment(t *testing.T) {
	c, err := Parse([]string{"--listen=127.0.0.1:8080", "--proxy-to=127.0.0.1:9000", "--metrics", "--enable-redis=false", "--tls=false"}, map[string]string{"PF_LISTEN": "127.0.0.1:9090", "PF_ENABLE_REDIS": "true", "DOS_DETECTOR_HOSTNAME_PENALTY_LIFETIME": "30m"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Listen != "127.0.0.1:8080" || c.Proxy.Upstream != "http://127.0.0.1:9000" || c.Redis.Enabled || c.TLS.Enabled || !c.Observability.Metrics || c.Firewall.PenaltyLifetime != 30*time.Minute {
		t.Fatalf("unexpected parsed configuration: listen=%s upstream=%s", c.HTTP.Listen, c.Proxy.Upstream)
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"network":              {"IP_FILTER_WHITELIST_NETWORKS": "bad-cidr"},
		"timeout":              {"REDIS_TIMEOUT": "-1s"},
		"boolean":              {"PF_TLS_ENABLED": "perhaps"},
		"budget":               {"PF_MAX_BUFFERED_BYTES": "1024"},
		"upstream credentials": {"PF_PROXY_TO": "http://user:secret@localhost:8080"},
		"upstream path":        {"PF_PROXY_TO": "http://localhost:8080/path"},
		"body overflow":        {"CVE_MITIGATOR_MAX_BODY_BYTES": "9223372036854775807"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(nil, values, io.Discard); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestEmptyCSVAndLocalDefaults(t *testing.T) {
	c, err := Parse(nil, map[string]string{"IP_FILTER_WHITELIST_NETWORKS": " , ", "IP_FILTER_ALLOWED_COUNTRIES": "Azerbaijan, Turkey, "}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Firewall.WhitelistNetworks) != 2 || len(c.Firewall.AllowedCountries) != 2 || c.Firewall.AllowedCountries[1] != "Turkey" {
		t.Fatal("CSV parsing failed")
	}
	if c.Redis.Enabled || c.Firewall.TrustCloudflareHeader {
		t.Fatal("unexpected external trust enabled")
	}
}

func TestSecretNotIncludedInValidationError(t *testing.T) {
	_, err := Parse(nil, map[string]string{"PF_PROXY_TO": "http://user:do-not-echo@localhost:8080"}, io.Discard)
	if err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatal("secret included in error")
	}
}

func TestEmptyAddressDisablesOptionalListenersAndSources(t *testing.T) {
	c, err := Parse(nil, map[string]string{"PF_PPROF_ADDRESS": "", "PF_GOOGLE_RANGES_URL": ""}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Observability.PprofAddress != "" || c.Intelligence.GoogleRangesURL != "" {
		t.Fatal("optional source/listener was not disabled")
	}
}

func TestRoutesAndStaticTLSConfiguration(t *testing.T) {
	c, err := Parse([]string{"--upstream-routes=WWW.Example.test.=internal-a:8080,api.example.test=https://internal-b:8443", "--tls-cert=/certs/server.pem", "--tls-key=/certs/server.key"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.Routes["www.example.test"] != "http://internal-a:8080" || c.Proxy.Routes["api.example.test"] != "https://internal-b:8443" || c.TLS.CertificateFile != "/certs/server.pem" || c.TLS.PrivateKeyFile != "/certs/server.key" {
		t.Fatal("route/TLS parsing failed")
	}
	for _, values := range []map[string]string{
		{"PF_UPSTREAM_ROUTES": "bad-entry"},
		{"PF_UPSTREAM_ROUTES": "example.test=http://first,EXAMPLE.test=http://second"},
		{"PF_UPSTREAM_ROUTES": "example.test=http://user:secret@internal"},
		{"PF_UPSTREAM_ROUTES": "example.test=http://internal/path"},
		{"PF_TLS_CERT_FILE": "/certificate-only.pem"},
	} {
		if _, err := Parse(nil, values, io.Discard); err == nil {
			t.Fatal("invalid route/TLS configuration accepted")
		}
	}
}

func TestAdminCredentialsAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".creds")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("operator:private-value\n")
	c, err := Parse(nil, map[string]string{"PF_ADMIN_CREDS_FILE": path, "PF_ADMIN_MAX_HOSTS": "128"}, io.Discard)
	if err != nil || !c.Admin.Enabled || c.Admin.MaxHosts != 128 || c.Admin.User != "operator" || c.Admin.Password != "private-value" {
		t.Fatal("admin credentials file configuration failed")
	}
	write("operator: spaced:password \r\n")
	c, err = Parse(nil, map[string]string{"PF_ADMIN_CREDS_FILE": path}, io.Discard)
	if err != nil || c.Admin.Password != " spaced:password " {
		t.Fatal("admin password bytes changed during parsing")
	}
	c, err = Parse(nil, map[string]string{"PF_ADMIN_CREDS_FILE": path, "PF_ADMIN_ENABLED": "false"}, io.Discard)
	if err != nil || c.Admin.Enabled || c.Admin.User != "operator" {
		t.Fatal("admin disable override lost credentials needed for stripping")
	}
	for _, values := range []map[string]string{
		{"PF_ADMIN_CREDS_FILE": filepath.Join(t.TempDir(), "missing")},
		{"PF_ADMIN_ENABLED": "true"},
		{"PF_ADMIN_MAX_HOSTS": "0"},
		{"PF_ADMIN_MAX_HOSTS": "1000001"},
	} {
		_, err := Parse(nil, values, io.Discard)
		if err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("invalid admin configuration accepted or credential exposed")
		}
	}
	for _, invalid := range []string{"", "operator", ":private-value", "operator:", "operator:private-value\nsecond:line", "operator:private-value\n\n", "operator:private-value\x00", "operator:" + strings.Repeat("private-value", 500)} {
		write(invalid)
		_, err := Parse(nil, map[string]string{"PF_ADMIN_CREDS_FILE": path}, io.Discard)
		if err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("malformed credentials accepted or contents exposed")
		}
	}
	c, err = Parse(nil, nil, io.Discard)
	if err != nil || c.Admin.Enabled {
		t.Fatal("admin must be disabled without a configured credentials file")
	}
}

func TestLoadReadsRelativeCredentialsOnceAtStartup(t *testing.T) {
	t.Chdir(t.TempDir())
	for name, content := range map[string]string{".env": "PF_ADMIN_CREDS_FILE=.creds\n", ".creds": "operator:first:password\n"} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(nil, io.Discard)
	if err != nil || !c.Admin.Enabled || c.Admin.User != "operator" || c.Admin.Password != "first:password" {
		t.Fatal("relative credentials file was not read at startup")
	}
	if err := os.WriteFile(".creds", []byte("operator:second-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if c.Admin.Password != "first:password" {
		t.Fatal("startup credentials changed without reloading")
	}
	next, err := Load(nil, io.Discard)
	if err != nil || next.Admin.Password != "second-password" {
		t.Fatal("next startup did not read updated credentials")
	}
}
