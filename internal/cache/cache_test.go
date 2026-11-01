package cache

import (
	"sync"
	"testing"
	"time"
)

func TestExpiryAndLRUEviction(t *testing.T) {
	now := time.Unix(100, 0)
	c := New[string, int](2)
	c.Set("a", 1, now.Add(time.Minute), now)
	c.Set("b", 2, now.Add(time.Hour), now)
	if got, ok := c.Get("a", now); !ok || got != 1 {
		t.Fatalf("a: %d, %v", got, ok)
	}
	c.Set("c", 3, now.Add(time.Hour), now)
	if _, ok := c.Get("b", now); ok {
		t.Fatal("least recently used value survived eviction")
	}
	if _, ok := c.Get("a", now.Add(time.Minute)); ok {
		t.Fatal("value survived its exact expiry")
	}
	c.Set("c", 4, now, now)
	if _, ok := c.Get("c", now); ok {
		t.Fatal("expired replacement did not remove value")
	}
}

func TestDisabledCache(t *testing.T) {
	now := time.Now()
	for _, capacity := range []int{0, -1} {
		c := New[int, int](capacity)
		c.Set(1, 1, now.Add(time.Hour), now)
		if _, ok := c.Get(1, now); ok {
			t.Fatal("disabled cache retained a value")
		}
	}
}

func TestConcurrentAccessRemainsBounded(t *testing.T) {
	c := New[int, int](16)
	now := time.Now()
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := worker*500 + i
				c.Set(key, i, now.Add(time.Minute), now)
				c.Get(key, now)
				c.Set(key+1, i, now, now)
			}
		}(worker)
	}
	wg.Wait()
	if len(c.items) > 16 || c.lru.Len() != len(c.items) {
		t.Fatalf("cache size=%d, list size=%d", len(c.items), c.lru.Len())
	}
}
