package ipfirewall

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDailyRefreshRetainsLastGoodListsAndRestoresCache(t *testing.T) {
	clock := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	requests, fail := 0, false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		status, body := 200, "203.0.113.0/24,US,US-NY,New York,\n2001:db8::/32,US,US-NY,New York,\n"
		if fail {
			status, body = 503, "unavailable"
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	cache := filepath.Join(t.TempDir(), "networks.json")
	service := New(cache, nil, WithHTTPClient(client))
	service.providers, service.now = catalog[:1], func() time.Time { return clock }
	if delay := service.refreshDue(context.Background()); delay != RefreshInterval || requests != 1 {
		t.Fatalf("first update: requests=%d delay=%v", requests, delay)
	}
	if service.Match(netip.MustParseAddr("203.0.113.255"), []string{"digitalocean"}) != "digitalocean" || service.Match(netip.MustParseAddr("2001:db8:ffff::1"), []string{"digitalocean"}) == "" || service.Match(netip.MustParseAddr("203.0.113.1"), nil) != "" {
		t.Fatal("provider selection or IPv4/IPv6 membership failed")
	}
	clock = clock.Add(23 * time.Hour)
	if delay := service.refreshDue(context.Background()); requests != 1 || delay != time.Hour {
		t.Fatalf("provider fetched more than once per day: requests=%d delay=%v", requests, delay)
	}
	restored := New(cache, nil, WithHTTPClient(client))
	restored.providers, restored.now = catalog[:1], service.now
	if err := restored.loadCache(); err != nil {
		t.Fatal(err)
	}
	restored.refreshDue(context.Background())
	if requests != 1 || restored.Match(netip.MustParseAddr("203.0.113.1"), []string{"digitalocean"}) == "" {
		t.Fatal("restart lost cache or downloaded a fresh list again")
	}
	clock, fail = clock.Add(time.Hour), true
	restored.refreshDue(context.Background())
	status := restored.Status().Providers[0]
	if requests != 2 || status.Error == "" || status.LastSuccess != clock.Add(-RefreshInterval) || restored.Match(netip.MustParseAddr("203.0.113.1"), []string{"digitalocean"}) == "" {
		t.Fatalf("failed refresh replaced last good data: %+v", status)
	}
	restored.refreshDue(context.Background())
	if requests != 2 {
		t.Fatal("failed provider was retried within the day")
	}
	if info, err := os.Stat(cache); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cache must be private")
	}
	reloaded := New(cache, nil)
	reloaded.now = service.now
	if err := reloaded.loadCache(); err != nil || reloaded.Match(netip.MustParseAddr("203.0.113.1"), []string{"digitalocean"}) == "" {
		t.Fatal("last valid ranges did not survive a failed update and restart", err)
	}
}

func TestWorkerCancelsInFlightDownloadAndStops(t *testing.T) {
	started := make(chan struct{})
	service := New("", nil, WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}))
	service.providers = catalog[:1]
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker never started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Stop(ctx); err != nil || service.Status().Running {
		t.Fatal("worker failed to stop", err)
	}
}

func TestNetworkBoundariesAndMappedAddresses(t *testing.T) {
	networks, err := Compile([]string{"203.0.113.4/24", "203.0.113.128/25", "::ffff:198.51.100.0/120", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"203.0.113.0", "203.0.113.255", "::ffff:203.0.113.8", "198.51.100.255", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !networks.Contains(netip.MustParseAddr(value)) {
			t.Errorf("missing address %s", value)
		}
	}
	for _, value := range []string{"203.0.112.255", "203.0.114.0", "198.51.101.0", "2001:db9::", "fe80::1%en0"} {
		if networks.Contains(netip.MustParseAddr(value)) {
			t.Errorf("unexpected address %s", value)
		}
	}
	// IPv6 interval endpoints must stay IPv6 even if the last address happens
	// to have an IPv4-mapped representation.
	boundary, err := Compile([]string{"::fffe:0:0/95"})
	if err != nil || !boundary.Contains(netip.MustParseAddr("::fffe:0:1")) {
		t.Fatal("IPv6 interval endpoint changed address family", err)
	}
	providers, entries, err := NormalizeSettings([]string{"AWS", "aws"}, []string{"203.0.113.5/24", "::ffff:198.51.100.1", "2001:db8::1"})
	if err != nil || !reflect.DeepEqual(providers, []string{"aws"}) || !reflect.DeepEqual(entries, []string{"203.0.113.0/24", "198.51.100.1", "2001:db8::1"}) {
		t.Fatalf("normalization: %v %v %v", providers, entries, err)
	}
	for _, value := range []string{"fe80::1%en0", "1.2.3.4/33", "all", "::ffff:192.0.2.0/80"} {
		if _, _, err := NormalizeSettings(nil, []string{value}); err == nil {
			t.Errorf("accepted invalid custom entry %s", value)
		}
	}
}

func TestCloudflareWorkersDoesNotBlockOrdinaryCDNVisitors(t *testing.T) {
	service := New("", nil)
	networks, _ := Compile([]string{"173.245.48.0/20"})
	service.publish("cloudflare_workers", providerState{networks: networks})
	peer, client := netip.MustParseAddr("173.245.48.1"), netip.MustParseAddr("203.0.113.8")
	if service.Match(peer, []string{"cloudflare_workers"}) != "" || service.IsCloudflareWorker(peer, client, false) {
		t.Fatal("ordinary CDN request treated as a Worker")
	}
	if !service.IsCloudflareWorker(peer, client, true) || !service.IsCloudflareWorker(peer, workersClientIP, false) || service.IsCloudflareWorker(client, client, true) {
		t.Fatal("Workers identification or untrusted-header rejection failed")
	}
}

func TestConcurrentReadersDuringProviderReplacement(t *testing.T) {
	service := New("", nil)
	networks, _ := Compile([]string{"203.0.113.0/24"})
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for range 100 {
				if worker == 0 {
					service.publish("digitalocean", providerState{networks: networks})
				} else {
					service.Match(netip.MustParseAddr("203.0.113.8"), []string{"digitalocean"})
					service.Status()
				}
			}
		})
	}
	wg.Wait()
}

func TestProviderFeedsLive(t *testing.T) {
	if os.Getenv("PF_TEST_LIVE_PROVIDER_FEEDS") != "1" {
		t.Skip("set PF_TEST_LIVE_PROVIDER_FEEDS=1 to verify public sources")
	}
	service := New("", nil)
	for _, p := range catalog {
		t.Run(p.ID, func(t *testing.T) {
			records, err := service.fetchProvider(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(fmt.Sprintf("%s: %d validated prefixes", p.Name, len(records)))
		})
	}
}
