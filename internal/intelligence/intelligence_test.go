package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
)

type testDatabase struct {
	country string
	lookup  func()
	closed  atomic.Int32
	lookups atomic.Int32
}

func (db *testDatabase) Lookup(ip net.IP, value any) error {
	db.lookups.Add(1)
	if db.lookup != nil {
		db.lookup()
	}
	value.(*countryResult).Country.Names.EN = db.country
	return nil
}
func (db *testDatabase) Close() error { db.closed.Add(1); return nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func newService(t *testing.T, cfg config.Config) *Service {
	t.Helper()
	s, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stopService(t *testing.T, s *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleLoadsLocalDatabaseWithoutOutboundSources(t *testing.T) {
	s := newService(t, config.Config{Intelligence: config.Intelligence{DatabasePath: "local.mmdb"}})
	db := &testDatabase{country: "Portugal"}
	var opened atomic.Int32
	s.openDB = func(path string) (countryDatabase, error) { opened.Add(1); return db, nil }
	s.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		t.Error("disabled sources made an HTTP request")
		return nil, errors.New("unexpected request")
	})
	if opened.Load() != 0 {
		t.Fatal("constructor opened database")
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("1.2.3.4")
	if got := s.Country(context.Background(), ip); got != "Portugal" {
		t.Fatalf("country=%q", got)
	}
	if got := s.Country(context.Background(), ip); got != "Portugal" || db.lookups.Load() != 1 {
		t.Fatal("country cache missed")
	}
	if opened.Load() != 1 {
		t.Fatal("Start was not idempotent")
	}
	stopService(t, s)
	stopService(t, s)
	if db.closed.Load() != 1 {
		t.Fatal("database was not closed exactly once")
	}
}

func TestDatabaseReplacementWaitsForLookup(t *testing.T) {
	s := newService(t, config.Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	old := &testDatabase{country: "Old", lookup: func() { close(entered); <-release }}
	s.replaceDB(old)
	lookupDone := make(chan struct{})
	go func() { s.Country(context.Background(), netip.MustParseAddr("1.2.3.4")); close(lookupDone) }()
	<-entered
	replacement := &testDatabase{country: "New"}
	swapDone := make(chan struct{})
	go func() { s.replaceDB(replacement); close(swapDone) }()
	if old.closed.Load() != 0 {
		t.Fatal("closed an in-use database")
	}
	close(release)
	<-lookupDone
	<-swapDone
	if old.closed.Load() != 1 {
		t.Fatal("retired database was not closed")
	}
	if got := s.Country(context.Background(), netip.MustParseAddr("2.3.4.5")); got != "New" {
		t.Fatal(got)
	}
	s.replaceDB(nil)
}

func TestMissingLocalDatabaseDegradesWithoutFailingStart(t *testing.T) {
	s := newService(t, config.Config{Intelligence: config.Intelligence{DatabasePath: filepath.Join(t.TempDir(), "missing.mmdb")}})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Country(context.Background(), netip.MustParseAddr("1.2.3.4")); got != "" {
		t.Fatal(got)
	}
	if s.IsGoogleBot(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("empty ranges allowed address")
	}
	stopService(t, s)
}

func TestGoogleRefreshReplacesSnapshotAndPreservesItOnFailure(t *testing.T) {
	var document atomic.Value
	document.Store(`{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"},{"ipv6Prefix":"2001:4860:4801::/48"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, document.Load().(string))
	}))
	defer server.Close()
	s := newService(t, config.Config{Intelligence: config.Intelligence{GoogleRangesURL: server.URL}})
	for i := 0; i < 20; i++ {
		if err := s.refreshGoogle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(s.google.Load().records); got != 2 {
		t.Fatalf("ranges accumulated: %d", got)
	}
	for _, raw := range []string{"66.249.64.0", "66.249.95.255", "::ffff:66.249.64.1", "2001:4860:4801::1"} {
		if !s.IsGoogleBot(netip.MustParseAddr(raw)) {
			t.Fatalf("missed %s", raw)
		}
	}
	for _, raw := range []string{"66.249.63.255", "66.249.96.0", "2001:4860:4802::1"} {
		if s.IsGoogleBot(netip.MustParseAddr(raw)) {
			t.Fatalf("allowed %s", raw)
		}
	}
	for _, invalid := range []string{`{`, `{"prefixes":[]}`, `{"prefixes":[{"ipv4Prefix":"invalid"}]}`, `{"prefixes":[{}]}`} {
		document.Store(invalid)
		if err := s.refreshGoogle(context.Background()); err == nil {
			t.Fatal("accepted invalid ranges")
		}
		if !s.IsGoogleBot(netip.MustParseAddr("66.249.64.1")) {
			t.Fatal("failure destroyed working ranges")
		}
	}
	document.Store(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`)
	if err := s.refreshGoogle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.IsGoogleBot(netip.MustParseAddr("66.249.64.1")) || !s.IsGoogleBot(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("refresh did not replace old snapshot")
	}
}

func TestMergedGoogleIntervalsAndConcurrentPublication(t *testing.T) {
	s := newService(t, config.Config{})
	snapshot, err := parseGoogleRecords([]string{"10.1.0.0/16", "10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.records) != 3 || len(snapshot.v4) != 1 {
		t.Fatal("ranges not deduplicated and merged")
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				s.google.Store(snapshot)
				s.IsGoogleBot(netip.MustParseAddr("10.9.8.7"))
				s.IsGoogleBot(netip.MustParseAddr("2001:db8::1"))
			}
		}()
	}
	wg.Wait()
	if !s.IsGoogleBot(netip.MustParseAddr("10.255.255.255")) || s.IsGoogleBot(netip.MustParseAddr("11.0.0.0")) {
		t.Fatal("merged interval bounds")
	}
}

type closingBody struct {
	io.Reader
	closed atomic.Bool
}

func (body *closingBody) Close() error { body.closed.Store(true); return nil }

func TestGoogleHTTPFailuresCloseBodiesAndKeepSnapshot(t *testing.T) {
	for _, testcase := range []struct {
		name   string
		status int
		data   string
	}{
		{"status", 503, "unavailable"},
		{"json", 200, "broken"},
		{"oversized", 200, strings.Repeat("x", maxGoogleBytes+1)},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			s := newService(t, config.Config{Intelligence: config.Intelligence{GoogleRangesURL: "https://example.invalid/ranges"}})
			body := &closingBody{Reader: strings.NewReader(testcase.data)}
			s.client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: testcase.status, Body: body, Header: make(http.Header), ContentLength: -1}, nil
			})
			if err := s.refreshGoogle(context.Background()); err == nil {
				t.Fatal("bad response accepted")
			}
			if !body.closed.Load() {
				t.Fatal("response body leaked")
			}
		})
	}
}

func TestHTTPTimeoutAndCanceledBackoff(t *testing.T) {
	s := newService(t, config.Config{Intelligence: config.Intelligence{HTTPTimeout: 10 * time.Millisecond, GoogleRangesURL: "https://example.invalid/ranges"}})
	s.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	if err := s.refreshGoogle(context.Background()); err == nil {
		t.Fatal("timeout did not fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		s.runRefresh(ctx, "test", func(context.Context) error { attempts.Add(1); return errors.New("failed") })
		close(done)
	}()
	timer := time.NewTimer(25 * time.Millisecond)
	<-timer.C
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backoff ignored cancellation")
	}
	if attempts.Load() != 1 {
		t.Fatalf("retry storm: %d attempts", attempts.Load())
	}
}

type archiveEntry struct {
	name string
	data string
	kind byte
}

func archiveBytes(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: 0600, Typeflag: kind, Size: int64(len(entry.data))}
		if kind != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := io.WriteString(tw, entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestArchiveExtractionRejectsUnsafeAndAmbiguousEntries(t *testing.T) {
	for _, testcase := range []struct {
		name    string
		entries []archiveEntry
	}{
		{"traversal", []archiveEntry{{name: "../escape.mmdb", data: "db"}}},
		{"absolute", []archiveEntry{{name: "/escape.mmdb", data: "db"}}},
		{"windows", []archiveEntry{{name: "C:\\escape.mmdb", data: "db"}}},
		{"link", []archiveEntry{{name: "data.mmdb", kind: tar.TypeSymlink}}},
		{"multiple", []archiveEntry{{name: "one.mmdb", data: "db"}, {name: "two.mmdb", data: "db"}}},
		{"empty", []archiveEntry{{name: "README", data: "no database"}}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			if _, err := extractMMDB(bytes.NewReader(archiveBytes(t, testcase.entries...)), t.TempDir()); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	valid := archiveBytes(t, archiveEntry{name: "GeoLite2-Country_20260101/GeoLite2-Country.mmdb", data: "database"})
	path, err := extractMMDB(bytes.NewReader(valid), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "database" {
		t.Fatalf("extraction: %q, %v", content, err)
	}
	if _, err := extractMMDB(bytes.NewReader(valid[:len(valid)-5]), t.TempDir()); err == nil {
		t.Fatal("truncated gzip accepted")
	}
}

func TestMaxMindUpdatePreservesWorkingDatabaseAndInstallsAtomically(t *testing.T) {
	var payload atomic.Value
	payload.Store(archiveBytes(t, archiveEntry{name: "GeoLite2-Country.mmdb", data: "invalid"}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.Write(payload.Load().([]byte)) }))
	defer server.Close()
	directory := t.TempDir()
	destination := filepath.Join(directory, "geo.mmdb")
	if err := os.WriteFile(destination, []byte("working"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newService(t, config.Config{Intelligence: config.Intelligence{DatabasePath: destination, MaxMindLicenseKey: "test-license"}})
	s.maxMindEndpoint = server.URL
	old := &testDatabase{country: "Old"}
	s.replaceDB(old)
	var replacement *testDatabase
	s.openDB = func(path string) (countryDatabase, error) {
		if !s.DatabaseStatus().Updating {
			t.Error("database refresh is not reported as updating")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "new" {
			return nil, errors.New("invalid database")
		}
		replacement = &testDatabase{country: "New"}
		return replacement, nil
	}
	if err := s.refreshMaxMind(context.Background()); err == nil {
		t.Fatal("invalid database accepted")
	}
	if s.DatabaseStatus().Updating {
		t.Fatal("failed refresh left updating status active")
	}
	if data, _ := os.ReadFile(destination); string(data) != "working" || old.closed.Load() != 0 {
		t.Fatal("failed refresh changed working database")
	}
	payload.Store(archiveBytes(t, archiveEntry{name: "release/GeoLite2-Country.mmdb", data: "new"}))
	if err := s.refreshMaxMind(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if status := s.DatabaseStatus(); err != nil || status.Updating || status.LastModified == nil || !status.LastModified.Equal(info.ModTime()) {
		t.Fatal("successful refresh does not report the installed file timestamp")
	}
	if data, _ := os.ReadFile(destination); string(data) != "new" || old.closed.Load() != 1 {
		t.Fatal("new database was not installed")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 || entries[0].Name() != "geo.mmdb" {
		t.Fatal("staging files leaked")
	}
	s.replaceDB(nil)
	if replacement.closed.Load() != 1 {
		t.Fatal("replacement reader leaked")
	}
}

func TestDownloadErrorsDoNotExposeLicenseURL(t *testing.T) {
	s := newService(t, config.Config{Intelligence: config.Intelligence{DatabasePath: filepath.Join(t.TempDir(), "geo.mmdb"), MaxMindLicenseKey: "test-license-private"}})
	s.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) { return nil, errors.New(req.URL.String()) })
	err := s.refreshMaxMind(context.Background())
	if err == nil || strings.Contains(err.Error(), "test-license") || strings.Contains(err.Error(), "license_key") {
		t.Fatalf("unsafe error text: %v", err)
	}
}
