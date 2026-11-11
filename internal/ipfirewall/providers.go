package ipfirewall

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

const (
	maxFeedBytes = 16 << 20
	maxPrefixes  = 100000
)

type feed struct{ url, format string }
type provider struct {
	ID, Name, Description string
	Feeds                 []feed
}

func announced(asns ...int) []feed {
	result := make([]feed, 0, len(asns))
	for _, asn := range asns {
		result = append(result, feed{fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn), "ripe"})
	}
	return result
}

// Prefer operator feeds; RIPE RIS announcements cover the listed ASNs where
// there is no operator feed. ASN coverage is explicit, not an ownership claim.
var catalog = []provider{
	{"digitalocean", "DigitalOcean", "DigitalOcean geofeed", []feed{{"https://www.digitalocean.com/geo/google.csv", "csv"}}},
	{"ovh", "OVH", "RIPE RIS: AS16276", announced(16276)},
	{"hetzner", "Hetzner", "RIPE RIS: AS24940, AS213230, AS212317, AS215859", announced(24940, 213230, 212317, 215859)},
	{"scaleway", "Scaleway", "RIPE RIS: AS12876", announced(12876)},
	{"hostman", "Hostman", "RIPE RIS: AS214504", announced(214504)},
	{"linode", "Linode", "Linode geofeed", []feed{{"https://geoip.linode.com/", "csv"}}},
	{"azure", "Azure", "Microsoft AzureCloud public-cloud service tag", []feed{{"https://www.microsoft.com/en-us/download/details.aspx?id=56519", "azure-page"}}},
	{"aws", "AWS", "AWS published IPv4 and IPv6 ranges", []feed{{"https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"}}},
	{"gcp", "GCP", "Google Cloud ranges only; Googlebot is excluded", []feed{{"https://www.gstatic.com/ipranges/cloud.json", "prefixes"}}},
	{"ionos", "IONOS", "RIPE RIS: AS8560, AS51862, AS54548", announced(8560, 51862, 54548)},
	{"meta", "Meta", "RIPE RIS: AS32934, AS63293", announced(32934, 63293)},
	{"openai_connectors", "OpenAI GPT Connectors", "OpenAI ChatGPT connectors feed", []feed{{"https://openai.com/chatgpt-connectors.json", "prefixes"}}},
	{"openai_agents", "OpenAI GPT Agents", "OpenAI ChatGPT agents feed", []feed{{"https://openai.com/chatgpt-agents.json", "prefixes"}}},
	{"alibaba", "Alibaba Cloud", "RIPE RIS: AS45102, AS37963", announced(45102, 37963)},
	{"cloudflare_workers", "Cloudflare Workers", "Workers identity or CF-Worker header from a verified Cloudflare edge; ordinary CDN traffic is allowed. Raw TCP Workers egress is not covered.", []feed{{"https://www.cloudflare.com/ips-v4", "lines"}, {"https://www.cloudflare.com/ips-v6", "lines"}}},
}

func knownProvider(id string) bool {
	for _, p := range catalog {
		if p.ID == id {
			return true
		}
	}
	return false
}

func (s *Service) fetch(ctx context.Context, source string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, errors.New("cannot construct network-list request")
	}
	req.Header.Set("User-Agent", "proxy-firewall-network-updater/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("network-list request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network-list server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxFeedBytes {
		return nil, errors.New("network list exceeds 16 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil || len(data) > maxFeedBytes {
		return nil, errors.New("cannot read network list within 16 MiB")
	}
	return data, nil
}

func (s *Service) fetchProvider(ctx context.Context, p provider) ([]string, error) {
	var records []string
	for _, source := range p.Feeds {
		data, err := s.fetch(ctx, source.url)
		if err != nil {
			return nil, err
		}
		format := source.format
		if format == "azure-page" {
			link, err := azureDownload(data)
			if err != nil {
				return nil, err
			}
			data, err = s.fetch(ctx, link)
			if err != nil {
				return nil, err
			}
			format = "azure"
		}
		entries, err := parseFeed(data, format)
		if err != nil {
			return nil, err
		}
		records = append(records, entries...)
		if len(records) > maxPrefixes {
			return nil, errors.New("provider exceeds 100000 prefixes")
		}
	}
	return validateRecords(records, true)
}

// Microsoft rotates the dated URL weekly. Discover it from the official page
// and restrict the download host and file name instead of freezing a dated URL.
var azureFile = regexp.MustCompile(`^ServiceTags_Public_[0-9]{8}\.json$`)

func azureDownload(data []byte) (string, error) {
	z := html.NewTokenizer(bytes.NewReader(data))
	for {
		typeValue := z.Next()
		if typeValue == html.ErrorToken {
			break
		}
		if typeValue != html.StartTagToken {
			continue
		}
		token := z.Token()
		if token.Data != "a" {
			continue
		}
		for _, attr := range token.Attr {
			if attr.Key != "href" {
				continue
			}
			u, err := url.Parse(attr.Val)
			if err == nil && u.Scheme == "https" && u.Host == "download.microsoft.com" && u.User == nil && azureFile.MatchString(u.Path[strings.LastIndex(u.Path, "/")+1:]) {
				return u.String(), nil
			}
		}
	}
	return "", errors.New("Microsoft download page has no Azure service-tag link")
}

func parseFeed(data []byte, format string) ([]string, error) {
	var records []string
	switch format {
	case "csv":
		r := csv.NewReader(bytes.NewReader(data))
		r.Comment, r.FieldsPerRecord = '#', -1
		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil || len(row) < 2 {
				return nil, errors.New("invalid provider geofeed")
			}
			records = append(records, strings.TrimSpace(row[0]))
			if len(records) > maxPrefixes {
				return nil, errors.New("too many geofeed entries")
			}
		}
	case "lines":
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				records = append(records, line)
			}
		}
	case "prefixes", "aws":
		var doc struct {
			Prefixes []struct {
				V4 string `json:"ipv4Prefix"`
				V6 string `json:"ipv6Prefix"`
				IP string `json:"ip_prefix"`
			} `json:"prefixes"`
			IPv6 []struct {
				IP string `json:"ipv6_prefix"`
			} `json:"ipv6_prefixes"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return nil, errors.New("invalid provider JSON")
		}
		for _, entry := range doc.Prefixes {
			value := entry.IP
			if format == "prefixes" {
				if (entry.V4 == "") == (entry.V6 == "") {
					return nil, errors.New("invalid provider prefix entry")
				}
				value = entry.V4 + entry.V6
			}
			records = append(records, value)
		}
		for _, entry := range doc.IPv6 {
			records = append(records, entry.IP)
		}
	case "ripe":
		var doc struct {
			Status string `json:"status"`
			Data   struct {
				Prefixes []struct {
					Prefix string `json:"prefix"`
				} `json:"prefixes"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &doc) != nil || doc.Status != "ok" || doc.Data.Prefixes == nil {
			return nil, errors.New("invalid RIPE announcement response")
		}
		for _, entry := range doc.Data.Prefixes {
			records = append(records, entry.Prefix)
		}
	case "azure":
		var doc struct {
			Values []struct {
				Name       string `json:"name"`
				Properties struct {
					Prefixes []string `json:"addressPrefixes"`
				} `json:"properties"`
			} `json:"values"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return nil, errors.New("invalid Azure service-tag response")
		}
		for _, entry := range doc.Values {
			if entry.Name == "AzureCloud" {
				records = append(records, entry.Properties.Prefixes...)
			}
		}
	default:
		return nil, errors.New("unknown network-list format")
	}
	return validateRecords(records, format != "ripe")
}

func validateRecords(records []string, requireNonempty bool) ([]string, error) {
	if requireNonempty && len(records) == 0 || len(records) > maxPrefixes {
		return nil, errors.New("network list is empty or exceeds 100000 prefixes")
	}
	seen := make(map[string]bool, len(records))
	result := make([]string, 0, len(records))
	for _, raw := range records {
		prefix, err := parsePrefix(raw)
		if err != nil || !strings.Contains(raw, "/") || prefix.Bits() == 0 {
			return nil, errors.New("network list contains an invalid or default-route prefix")
		}
		value := prefix.String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}
