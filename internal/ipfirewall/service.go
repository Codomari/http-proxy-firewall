package ipfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const RefreshInterval = 24 * time.Hour
const maxCacheBytes = 32 << 20

type ProviderStatus struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Sources     []string  `json:"sources"`
	Prefixes    int       `json:"prefixes"`
	LastSuccess time.Time `json:"last_success"`
	LastAttempt time.Time `json:"last_attempt"`
	NextRefresh time.Time `json:"next_refresh"`
	Error       string    `json:"error"`
}

type Status struct {
	Running        bool             `json:"running"`
	RefreshSeconds int              `json:"refresh_seconds"`
	CacheError     string           `json:"cache_error"`
	Providers      []ProviderStatus `json:"providers"`
}

type providerState struct {
	Records     []string  `json:"records"`
	LastSuccess time.Time `json:"last_success"`
	LastAttempt time.Time `json:"last_attempt"`
	Error       string    `json:"error"`
	networks    *Networks
}

type snapshot struct {
	providers  map[string]providerState
	cacheError string
}

type Service struct {
	cachePath string
	logger    *slog.Logger
	client    *http.Client
	providers []provider
	now       func() time.Time
	state     atomic.Pointer[snapshot]
	running   atomic.Bool
	lifeMu    sync.Mutex
	started   bool
	stopped   bool
	cancel    context.CancelFunc
	done      chan struct{}
}

type Option func(*Service)

// WithHTTPClient permits an injected transport for controlled integrations.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Service) {
		if client != nil {
			s.client = client
		}
	}
}

// New performs no I/O; Start restores the cache before launching the worker.
func New(cachePath string, logger *slog.Logger, options ...Option) *Service {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Service{cachePath: cachePath, logger: logger, providers: catalog, now: time.Now,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("unsafe network-list redirect rejected")
			}
			return nil
		}},
	}
	s.state.Store(&snapshot{providers: map[string]providerState{}})
	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Service) Start(ctx context.Context) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.stopped {
		return errors.New("IP Firewall worker already stopped")
	}
	if s.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.loadCache(); err != nil {
		s.state.Store(&snapshot{providers: map[string]providerState{}, cacheError: "Unable to read network cache; waiting for downloads"})
		s.logger.Warn("IP Firewall network cache unavailable", "error", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done, s.started = cancel, make(chan struct{}), true
	s.running.Store(true)
	go func() {
		defer close(s.done)
		defer s.running.Store(false)
		s.run(runCtx)
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

func (s *Service) run(ctx context.Context) {
	for ctx.Err() == nil {
		delay := s.refreshDue(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Each provider is attempted at most once per day, including after failures or
// restarts. Persist the attempt before fetching; retain last good ranges on error.
// This single worker serializes updates and bounds memory and external requests.
func (s *Service) refreshDue(ctx context.Context) time.Duration {
	for _, p := range s.providers {
		if ctx.Err() != nil {
			return RefreshInterval
		}
		now := s.now().UTC()
		previous := s.state.Load().providers[p.ID]
		if previous.LastAttempt.Add(RefreshInterval).After(now) {
			continue
		}
		previous.LastAttempt = now
		s.publish(p.ID, previous)
		s.persist()
		records, err := s.fetchProvider(ctx, p)
		if ctx.Err() != nil {
			return RefreshInterval
		}
		if err != nil {
			previous.Error = err.Error()
			s.logger.Warn("IP Firewall provider refresh failed", "provider", p.ID, "error", err)
		} else {
			previous.Records, previous.LastSuccess, previous.Error = records, s.now().UTC(), ""
			previous.networks, _ = Compile(records) // fetchProvider already validated.
		}
		s.publish(p.ID, previous)
		s.persist()
	}
	until := RefreshInterval
	for _, p := range s.providers {
		state := s.state.Load().providers[p.ID]
		delay := state.LastAttempt.Add(RefreshInterval).Sub(s.now())
		if delay < until {
			until = delay
		}
	}
	return max(until, time.Second)
}

func (s *Service) publish(id string, state providerState) {
	old := s.state.Load()
	next := &snapshot{providers: make(map[string]providerState, len(old.providers)+1), cacheError: old.cacheError}
	for key, value := range old.providers {
		next.providers[key] = value
	}
	next.providers[id] = state
	s.state.Store(next)
}

func (s *Service) Status() Status {
	state := s.state.Load()
	result := Status{Running: s.running.Load(), RefreshSeconds: int(RefreshInterval / time.Second), CacheError: state.cacheError, Providers: make([]ProviderStatus, 0, len(s.providers))}
	for _, p := range s.providers {
		entry := state.providers[p.ID]
		status := ProviderStatus{ID: p.ID, Name: p.Name, Description: p.Description, Sources: []string{}, Prefixes: len(entry.Records), LastSuccess: entry.LastSuccess, LastAttempt: entry.LastAttempt, Error: entry.Error}
		if !entry.LastAttempt.IsZero() {
			status.NextRefresh = entry.LastAttempt.Add(RefreshInterval)
		}
		for _, source := range p.Feeds {
			status.Sources = append(status.Sources, source.url)
		}
		result.Providers = append(result.Providers, status)
	}
	return result
}

func (s *Service) Match(ip netip.Addr, selected []string) string {
	state := s.state.Load()
	for _, id := range selected {
		// Cloudflare's published edge ranges also carry ordinary CDN visitors.
		// Workers require the extra identity checks in IsCloudflareWorker.
		if id != "cloudflare_workers" && state.providers[id].networks.Contains(ip) {
			return id
		}
	}
	return ""
}

var workersClientIP = netip.MustParseAddr("2a06:98c0:3600::103")

func (s *Service) IsCloudflareWorker(peer, client netip.Addr, hasWorkerHeader bool) bool {
	if client == workersClientIP {
		return true
	}
	return hasWorkerHeader && s.state.Load().providers["cloudflare_workers"].networks.Contains(peer)
}

func (s *Service) loadCache() error {
	if s.cachePath == "" {
		return nil
	}
	f, err := os.Open(s.cachePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCacheBytes {
		return errors.New("invalid IP Firewall cache file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
	if err != nil || len(data) > maxCacheBytes {
		return errors.New("IP Firewall cache exceeds 32 MiB")
	}
	var cache struct {
		Version   int                      `json:"version"`
		Providers map[string]providerState `json:"providers"`
	}
	if json.Unmarshal(data, &cache) != nil || cache.Version != 1 || len(cache.Providers) > len(catalog) {
		return errors.New("invalid IP Firewall cache")
	}
	for id, entry := range cache.Providers {
		if !knownProvider(id) || entry.LastAttempt.After(s.now().Add(time.Minute)) || entry.LastSuccess.After(entry.LastAttempt.Add(10*time.Minute)) || len(entry.Error) > 256 {
			return errors.New("invalid IP Firewall cache entry")
		}
		entry.Records, err = validateRecords(entry.Records, false)
		if err != nil {
			return err
		}
		entry.networks, err = Compile(entry.Records)
		if err != nil {
			return err
		}
		cache.Providers[id] = entry
	}
	s.state.Store(&snapshot{providers: cache.Providers})
	return nil
}

func (s *Service) persist() {
	if s.cachePath == "" {
		return
	}
	err := s.saveCache()
	old := s.state.Load()
	message := ""
	if err != nil {
		message = "Unable to save network cache; downloaded lists remain active in memory"
		s.logger.Warn("IP Firewall network cache save failed", "error", err)
	}
	s.state.Store(&snapshot{providers: old.providers, cacheError: message})
}

func (s *Service) saveCache() error {
	data, err := json.Marshal(struct {
		Version   int                      `json:"version"`
		Providers map[string]providerState `json:"providers"`
	}{1, s.state.Load().providers})
	if err != nil || len(data) > maxCacheBytes {
		return errors.New("IP Firewall cache exceeds 32 MiB")
	}
	if err := os.MkdirAll(filepath.Dir(s.cachePath), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.cachePath), ".ip-firewall-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	if err := errors.Join(writeErr, syncErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.cachePath)
}
