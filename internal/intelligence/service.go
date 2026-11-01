// Package intelligence owns local country data and immutable Googlebot ranges.
package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/storage"
)

const (
	countryLifetime  = 24 * time.Hour
	unknownLifetime  = time.Hour
	googleStorageKey = "GOOGLEBOT:NETWORK"
)

type countryDatabase interface {
	Lookup(net.IP, any) error
	Close() error
}

type countryResult struct {
	Country struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"country"`
}

type countryRecord struct {
	Country string    `json:"country"`
	Expires time.Time `json:"expires"`
}

// Service must be started before use and stopped after request handling drains.
// Its constructor performs no file, network, or background work.
type Service struct {
	cfg       config.Config
	remote    *storage.Remote
	logger    *slog.Logger
	client    *http.Client
	countries *cache.Cache[netip.Addr, string]
	google    atomic.Pointer[googleSnapshot]

	dbMu            sync.RWMutex
	db              countryDatabase
	openDB          func(string) (countryDatabase, error)
	maxMindEndpoint string
	updating        atomic.Bool

	lifeMu  sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func New(cfg config.Config, remote *storage.Remote, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Intelligence.RefreshInterval <= 0 {
		cfg.Intelligence.RefreshInterval = 24 * time.Hour
	}
	if cfg.Intelligence.HTTPTimeout <= 0 {
		cfg.Intelligence.HTTPTimeout = 15 * time.Second
	}
	if cfg.Intelligence.GoogleRangesURL != "" {
		u, err := url.Parse(cfg.Intelligence.GoogleRangesURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			return nil, errors.New("invalid Google ranges URL")
		}
	}
	capacity := cfg.Firewall.CacheCapacity
	if capacity <= 0 {
		capacity = 10000
	}
	s := &Service{
		cfg: cfg, remote: remote, logger: logger,
		countries:       cache.New[netip.Addr, string](capacity),
		openDB:          func(path string) (countryDatabase, error) { return maxminddb.Open(path) },
		maxMindEndpoint: "https://download.maxmind.com/app/geoip_download",
		client: &http.Client{
			Timeout: cfg.Intelligence.HTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 || req.URL.Scheme != "https" {
					return errors.New("unsafe redirect rejected")
				}
				return nil
			},
		},
	}
	s.google.Store(&googleSnapshot{})
	return s, nil
}

// Country returns an English country name, or an empty string if unknown.
// The local MMDB handles cold lookups without a Redis round trip. Redis supplies
// a fallback when a local database is unavailable.
func (s *Service) Country(ctx context.Context, ip netip.Addr) string {
	if !ip.IsValid() || ip.Zone() != "" {
		return ""
	}
	ip = ip.Unmap()
	now := time.Now()
	if country, ok := s.countries.Get(ip, now); ok {
		return country
	}
	var result countryResult
	s.dbMu.RLock()
	db := s.db
	found := db != nil && db.Lookup(net.IP(ip.AsSlice()), &result) == nil
	s.dbMu.RUnlock()
	if found {
		lifetime := countryLifetime
		if result.Country.Names.EN == "" {
			lifetime = unknownLifetime
		}
		record := countryRecord{Country: result.Country.Names.EN, Expires: now.Add(lifetime)}
		s.countries.Set(ip, record.Country, record.Expires, now)
		if s.remote != nil {
			data, _ := json.Marshal(record)
			s.remote.Set("IPTOCOUNTRY:"+ip.String(), data, lifetime)
		}
		return record.Country
	}
	if s.remote != nil {
		data, ok, err := s.remote.Get(ctx, "IPTOCOUNTRY:"+ip.String())
		if err == nil && ok && len(data) <= 4096 {
			var record countryRecord
			if json.Unmarshal(data, &record) == nil && record.Expires.After(now) && len(record.Country) <= 256 {
				// A remote value cannot extend the local retention indefinitely.
				expires := record.Expires
				if expires.After(now.Add(countryLifetime)) {
					expires = now.Add(countryLifetime)
				}
				s.countries.Set(ip, record.Country, expires, now)
				return record.Country
			}
		}
	}
	// Retry soon when a database is still being downloaded or Redis is offline.
	s.countries.Set(ip, "", now.Add(time.Minute), now)
	return ""
}

func (s *Service) Start(ctx context.Context) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.stopped {
		return errors.New("intelligence service already stopped")
	}
	if s.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Open the existing database before starting any network refresh.
	if path := s.cfg.Intelligence.DatabasePath; path != "" {
		if db, err := s.openDB(path); err == nil {
			s.replaceDB(db)
		} else {
			s.logger.Warn("local country database unavailable")
		}
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done, s.started = cancel, make(chan struct{}), true
	var wg sync.WaitGroup
	if s.cfg.Intelligence.GoogleRangesURL != "" || s.remote != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runGoogle(runCtx)
		}()
	}
	if s.cfg.Intelligence.MaxMindLicenseKey != "" && s.cfg.Intelligence.DatabasePath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runRefresh(runCtx, "country database", s.refreshMaxMind)
		}()
	}
	go func() {
		<-runCtx.Done()
		wg.Wait()
		s.replaceDB(nil)
		close(s.done)
	}()
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.lifeMu.Lock()
	s.stopped = true
	if !s.started {
		s.lifeMu.Unlock()
		return nil
	}
	s.cancel()
	done := s.done
	s.lifeMu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) replaceDB(next countryDatabase) {
	s.dbMu.Lock()
	previous := s.db
	s.db = next
	s.dbMu.Unlock()
	// Acquiring the write lock above waited for every lookup of the old reader.
	if previous != nil {
		_ = previous.Close()
	}
}

func (s *Service) runRefresh(ctx context.Context, name string, update func(context.Context) error) {
	retry := time.Second
	for ctx.Err() == nil {
		err := update(ctx)
		delay := s.cfg.Intelligence.RefreshInterval
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("intelligence refresh failed", "source", name, "error", err)
			delay = retry
			if retry < 5*time.Minute {
				retry *= 2
				if retry > 5*time.Minute {
					retry = 5 * time.Minute
				}
			}
		} else {
			retry = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// request deliberately returns errors without URLs: MaxMind URLs carry a key.
func (s *Service) request(ctx context.Context, source string, maxBytes int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, errors.New("cannot construct intelligence request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("intelligence HTTP request failed or timed out")
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("intelligence server returned a non-success status")
	}
	if resp.ContentLength > maxBytes {
		_ = resp.Body.Close()
		return nil, errors.New("intelligence response exceeds size limit")
	}
	return resp, nil
}
