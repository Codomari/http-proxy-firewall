package session

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"
	"unsafe"

	"http-proxy-firewall/internal/config"
)

func TestCompatibleSIDAndFixedExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := New(config.Config{}, nil)
	s.now = func() time.Time { return now }
	record, err := s.Issue(context.Background(), "example.test", "browser")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("example.test:" + record.Nonce + ":browser"))
	if expected := base64.URLEncoding.EncodeToString(digest[:]); record.SID != expected {
		t.Fatal("SID wire format changed")
	}
	if !record.Expires.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("default expiry = %v", record.Expires)
	}
	if !s.Validate(context.Background(), record.SID, "example.test", "browser") {
		t.Fatal("issued cookie was not accepted")
	}
	if s.Validate(context.Background(), record.SID, "other.test", "browser") || s.Validate(context.Background(), record.SID, "example.test", "other") {
		t.Fatal("SID was not bound to domain and user agent")
	}
	now = record.Expires.Add(-time.Nanosecond)
	if !s.Validate(context.Background(), record.SID, "example.test", "browser") {
		t.Fatal("cookie expired too early")
	}
	now = record.Expires
	if s.Validate(context.Background(), record.SID, "example.test", "browser") {
		t.Fatal("cookie remained valid at expiry")
	}
}

func TestV1RecordJSONAndConfiguredLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := config.Config{Firewall: config.Firewall{CookieLifetime: time.Minute, CacheCapacity: 2}}
	s := New(cfg, nil)
	s.now = func() time.Time { return now }
	nonce := "v1-nonce-0123456789012345678901234"
	sid := makeSID("example.test", nonce, "browser")
	data, _ := json.Marshal(map[string]any{"sid": sid, "nonce": nonce, "expires": now.Add(time.Minute)})
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	s.cache.Set(record.SID, record, record.Expires, now)
	if !s.Validate(context.Background(), sid, "example.test", "browser") {
		t.Fatal("v1 JSON record is incompatible")
	}
	issued, err := s.Issue(context.Background(), "example.test", "browser")
	if err != nil || issued.Nonce == nonce || !issued.Expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("configured lifetime or random nonce failed: %+v %v", issued, err)
	}
	second, err := s.Issue(context.Background(), "example.test", "browser")
	if err != nil || second.SID == issued.SID {
		t.Fatal("two new sessions shared a nonce")
	}
}

func TestSessionOwnsRetainedRequestData(t *testing.T) {
	s := New(config.Config{}, nil)
	domain := []byte("example.test")
	agent := []byte("browser")
	domainView := unsafe.String(unsafe.SliceData(domain), len(domain))
	agentView := unsafe.String(unsafe.SliceData(agent), len(agent))
	record, err := s.Issue(context.Background(), domainView, agentView)
	if err != nil {
		t.Fatal(err)
	}
	for i := range domain {
		domain[i] = 'x'
	}
	for i := range agent {
		agent[i] = 'x'
	}
	if !s.Validate(context.Background(), record.SID, "example.test", "browser") {
		t.Fatal("session retained mutable request data")
	}
}

func TestConcurrentIssueAndValidate(t *testing.T) {
	s := New(config.Config{Firewall: config.Firewall{CacheCapacity: 4096}}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				record, err := s.Issue(context.Background(), "example.test", "browser")
				if err != nil || !s.Validate(context.Background(), record.SID, "example.test", "browser") {
					t.Error("concurrent session failed", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
