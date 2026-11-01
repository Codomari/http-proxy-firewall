// Package session owns fixed-expiry challenge cookies. Request handling starts
// no background work: remote writes use storage's bounded worker queue.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"time"

	"http-proxy-firewall/internal/cache"
	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/storage"
)

const CookieName = "_X-SID_"

type Record struct {
	SID     string    `json:"sid"`
	Nonce   string    `json:"nonce"`
	Expires time.Time `json:"expires"`
}

type Service struct {
	cache    *cache.Cache[string, Record]
	remote   *storage.Remote
	lifetime time.Duration
	now      func() time.Time
}

func New(cfg config.Config, remote *storage.Remote) *Service {
	lifetime := cfg.Firewall.CookieLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	capacity := cfg.Firewall.CacheCapacity
	if capacity <= 0 {
		capacity = 100000
	}
	return &Service{
		cache: cache.New[string, Record](capacity), remote: remote,
		lifetime: lifetime, now: time.Now,
	}
}

func (s *Service) Lifetime() time.Duration { return s.lifetime }

// makeSID intentionally preserves the v1 domain:nonce:userAgent hash and padded
// URL-safe base64 encoding, so unexpired records remain usable across upgrades.
func makeSID(domain, nonce, userAgent string) string {
	digest := sha512.Sum512([]byte(domain + ":" + nonce + ":" + userAgent))
	return base64.URLEncoding.EncodeToString(digest[:])
}

func (s *Service) Issue(ctx context.Context, domain, userAgent string) (Record, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Record{}, err
	}
	now := s.now()
	nonce := base64.RawURLEncoding.EncodeToString(random[:])
	record := Record{SID: makeSID(domain, nonce, userAgent), Nonce: nonce, Expires: now.Add(s.lifetime)}
	s.cache.Set(record.SID, record, record.Expires, now)
	if s.remote != nil {
		if data, err := json.Marshal(record); err == nil {
			s.remote.Set("COOKIES:"+record.SID, data, s.lifetime)
		}
	}
	return record, nil
}

func (s *Service) Validate(ctx context.Context, sid, domain, userAgent string) bool {
	// A SHA-512 digest encoded with padded URL-safe base64 is always 88 bytes.
	if len(sid) != base64.URLEncoding.EncodedLen(sha512.Size) {
		return false
	}
	now := s.now()
	record, ok := s.cache.Get(sid, now)
	if !ok {
		if s.remote == nil {
			return false
		}
		data, found, err := s.remote.Get(ctx, "COOKIES:"+sid)
		if err != nil || !found || json.Unmarshal(data, &record) != nil {
			return false
		}
		if record.SID != sid || record.Nonce == "" || !now.Before(record.Expires) {
			return false
		}
		// Remote JSON owns these strings. No Fiber request-backed storage escapes.
		s.cache.Set(record.SID, record, record.Expires, now)
	}
	if !now.Before(record.Expires) {
		return false
	}
	expected := makeSID(domain, record.Nonce, userAgent)
	return subtle.ConstantTimeCompare([]byte(sid), []byte(expected)) == 1
}
