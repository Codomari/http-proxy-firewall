package ipfirewall

import (
	"strings"
	"testing"
)

func TestProviderFeedFormatsAndInvalidReplacements(t *testing.T) {
	for _, tc := range []struct {
		format, body string
		count        int
	}{
		{"prefixes", `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}`, 2},
		{"aws", `{"prefixes":[{"ip_prefix":"203.0.113.0/24"},{"ip_prefix":"203.0.113.0/24"}],"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32"}]}`, 2},
		{"ripe", `{"status":"ok","data":{"prefixes":[{"prefix":"203.0.113.0/24"}]}}`, 1},
		{"ripe", `{"status":"ok","data":{"prefixes":[]}}`, 0},
		{"azure", `{"values":[{"name":"OtherService","properties":{"addressPrefixes":["192.0.2.0/24"]}},{"name":"AzureCloud","properties":{"addressPrefixes":["203.0.113.0/24"]}}]}`, 1},
		{"csv", "# provider feed\n203.0.113.0/24,US,,Example City,\n2001:db8::/32,US,,,\n", 2},
		{"lines", "203.0.113.0/24\n2001:db8::/32\n", 2},
	} {
		records, err := parseFeed([]byte(tc.body), tc.format)
		if err != nil || len(records) != tc.count {
			t.Errorf("format=%s records=%v err=%v", tc.format, records, err)
		}
	}
	for _, tc := range []struct{ format, body string }{
		{"prefixes", `{"prefixes":[]}`},
		{"prefixes", `{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}`},
		{"prefixes", `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24","ipv6Prefix":"2001:db8::/32"}]}`},
		{"prefixes", `{"prefixes":[{"ipv4Prefix":"garbage"}]}`},
		{"ripe", `{"status":"error","data":{"prefixes":[]}}`},
		{"ripe", `{"status":"ok","data":{}}`},
		{"azure", `{"values":[{"name":"OtherService","properties":{"addressPrefixes":["203.0.113.0/24"]}}]}`},
		{"csv", "<html>server error</html>"},
		{"lines", "::/0"},
	} {
		if _, err := parseFeed([]byte(tc.body), tc.format); err == nil {
			t.Errorf("accepted invalid %s replacement: %s", tc.format, tc.body)
		}
	}
}

func TestAzureDownloadDiscoveryRejectsOtherHostsAndFiles(t *testing.T) {
	link := "https://download.microsoft.com/download/example/ServiceTags_Public_20261109.json"
	if got, err := azureDownload([]byte(`<a href="` + link + `">Download</a>`)); err != nil || got != link {
		t.Fatal("official dated link not discovered", got, err)
	}
	for _, invalid := range []string{strings.Replace(link, "https:", "http:", 1), strings.Replace(link, "download.microsoft.com", "download.microsoft.com.evil.test", 1), strings.Replace(link, "Public_20261109", "China_20261109", 1)} {
		if _, err := azureDownload([]byte(`<a href="` + invalid + `">Download</a>`)); err == nil {
			t.Fatal("accepted invalid Azure download", invalid)
		}
	}
}
