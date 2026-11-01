// Package cache provides a bounded, concurrency-safe TTL cache with LRU eviction.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// Cache owns its metadata, but callers remain responsible for the ownership of V.
// Values should be immutable when shared between goroutines.
type Cache[K comparable, V any] struct {
	mx       sync.Mutex
	capacity int
	items    map[K]*list.Element
	lru      list.List
}

type entry[K comparable, V any] struct {
	key     K
	value   V
	expires time.Time
}

// New creates a cache. A nonpositive capacity disables storage.
func New[K comparable, V any](capacity int) *Cache[K, V] {
	if capacity < 0 {
		capacity = 0
	}
	return &Cache[K, V]{capacity: capacity, items: make(map[K]*list.Element)}
}

// Get returns an unexpired value and marks it as most recently used.
func (c *Cache[K, V]) Get(key K, now time.Time) (V, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()
	var zero V
	e, ok := c.items[key]
	if !ok {
		return zero, false
	}
	record := e.Value.(*entry[K, V])
	if !record.expires.After(now) {
		c.remove(e)
		return zero, false
	}
	c.lru.MoveToFront(e)
	return record.value, true
}

// Set stores a value until expires. Already-expired values remove the key.
func (c *Cache[K, V]) Set(key K, value V, expires, now time.Time) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if !expires.After(now) {
		if e := c.items[key]; e != nil {
			c.remove(e)
		}
		return
	}
	if c.capacity == 0 {
		return
	}
	if e := c.items[key]; e != nil {
		record := e.Value.(*entry[K, V])
		record.value = value
		record.expires = expires
		c.lru.MoveToFront(e)
		return
	}
	if len(c.items) >= c.capacity {
		c.remove(c.lru.Back())
	}
	c.items[key] = c.lru.PushFront(&entry[K, V]{key: key, value: value, expires: expires})
}

func (c *Cache[K, V]) remove(e *list.Element) {
	delete(c.items, e.Value.(*entry[K, V]).key)
	c.lru.Remove(e)
}
