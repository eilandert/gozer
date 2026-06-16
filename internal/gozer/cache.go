package gozer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache is the /check verdict cache, keyed on sha256(body). /report and /revoke
// are never cached. Two implementations exist: an in-process TTL+LRU map
// (default) and a Redis-backed cache (shared across distributed scanners) that
// fronts Redis with the same in-process map as an L1.
type Cache interface {
	// Get returns the cached verdict bytes and true on a live hit.
	Get(key string) ([]byte, bool)
	// Put stores verdict bytes under key for the configured TTL.
	Put(key string, val []byte)
	// Delete invalidates a key so a stale /check verdict cannot survive a
	// /report or /revoke of the same message.
	Delete(key string)
}

// NewCache builds the cache backend for cfg. It returns nil (caching disabled)
// when CacheTTL <= 0. A Redis backend is used when RedisURL is set; if Redis
// cannot be initialised gozer logs and falls back to the in-process cache,
// so a misconfigured Redis never disables /check.
func NewCache(cfg *Config, logf func(string, ...any), m *Metrics) Cache {
	if cfg.CacheTTL <= 0 {
		return nil
	}
	mem := newMemCache(cfg.CacheSize, cfg.CacheTTL)
	if cfg.RedisURL == "" {
		return mem
	}
	rc, err := newRedisCache(cfg, mem)
	if err != nil {
		logf("Redis cache init failed (%v); using in-memory", err)
		return mem
	}
	rc.metrics = m
	return rc
}

// memCache is a size-bounded TTL cache with O(1) lookup, refresh and LRU
// eviction. Expired entries are removed on lookup or when they reach the LRU
// tail.
type memCache struct {
	mu   sync.Mutex
	d    map[string]*memEntry
	head *memEntry
	tail *memEntry
	size int
	ttl  time.Duration
}

type memEntry struct {
	key        string
	exp        time.Time
	data       []byte
	prev, next *memEntry
}

func newMemCache(size int, ttl time.Duration) *memCache {
	if size <= 0 {
		size = 4096
	}
	return &memCache{
		d:    make(map[string]*memEntry, size),
		size: size,
		ttl:  ttl,
	}
}

func (c *memCache) Get(key string) ([]byte, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.d[key]
	if !ok {
		return nil, false
	}
	if now.After(e.exp) {
		c.remove(e)
		return nil, false
	}
	c.moveToFront(e)
	return e.data, true
}

func (c *memCache) Put(key string, val []byte) {
	c.putTTL(key, val, c.ttl)
}

func (c *memCache) putTTL(key string, val []byte, ttl time.Duration) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.d[key]; ok {
		e.exp = now.Add(ttl)
		e.data = val
		c.moveToFront(e)
		return
	}
	if len(c.d) >= c.size {
		if c.tail != nil {
			c.remove(c.tail)
		}
	}
	e := &memEntry{key: key, exp: now.Add(ttl), data: val}
	c.d[key] = e
	c.pushFront(e)
}

func (c *memCache) Delete(key string) {
	c.mu.Lock()
	if e, ok := c.d[key]; ok {
		c.remove(e)
	}
	c.mu.Unlock()
}

func (c *memCache) pushFront(e *memEntry) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	} else {
		c.tail = e
	}
	c.head = e
}

func (c *memCache) moveToFront(e *memEntry) {
	if e == c.head {
		return
	}
	c.unlink(e)
	c.pushFront(e)
}

func (c *memCache) remove(e *memEntry) {
	c.unlink(e)
	delete(c.d, e.key)
}

func (c *memCache) unlink(e *memEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// redisCache fronts a shared Redis L2 with the in-process memCache as an L1.
// Every Redis call fails open: any error degrades to an L1 miss / no-store, so
// a Redis outage falls back to direct backend calls rather than an error.
type redisCache struct {
	rdb        *redis.Client
	l1         *memCache
	prefix     string
	ttl        time.Duration
	metrics    *Metrics // optional; nil-safe (Redis error/circuit counters)
	stateMu    sync.Mutex
	retryAfter time.Time
}

const (
	redisOpTimeout  = 100 * time.Millisecond
	redisRetryDelay = 5 * time.Second
)

func newRedisCache(cfg *Config, l1 *memCache) (*redisCache, error) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	// Redis is only a cache. Keep its budget far below backend latency and open
	// a short circuit after failures so an outage cannot tax every message.
	opt.DialTimeout = redisOpTimeout
	opt.ReadTimeout = redisOpTimeout
	opt.WriteTimeout = redisOpTimeout
	return &redisCache{
		rdb:    redis.NewClient(opt),
		l1:     l1,
		prefix: cfg.RedisPrefix,
		ttl:    cfg.CacheTTL,
	}, nil
}

func (c *redisCache) Get(key string) ([]byte, bool) {
	if v, ok := c.l1.Get(key); ok {
		return v, true
	}
	if !c.redisAllowed() {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	redisKey := c.prefix + key
	pipe := c.rdb.Pipeline()
	get := pipe.Get(ctx, redisKey)
	pttl := pipe.PTTL(ctx, redisKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			c.redisFailed()
		}
		return nil, false // miss or any Redis error -> fail open
	}
	v, err := get.Bytes()
	if err != nil {
		return nil, false
	}
	remaining := pttl.Val()
	if remaining <= 0 {
		return nil, false
	}
	if remaining > c.ttl {
		remaining = c.ttl
	}
	c.l1.putTTL(key, v, remaining)
	c.redisSucceeded()
	return v, true
}

func (c *redisCache) Put(key string, val []byte) {
	c.l1.Put(key, val)
	if !c.redisAllowed() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	if err := c.rdb.Set(ctx, c.prefix+key, val, c.ttl).Err(); err != nil {
		c.redisFailed()
		return
	}
	c.redisSucceeded()
}

func (c *redisCache) Delete(key string) {
	c.l1.Delete(key)
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	if err := c.rdb.Del(ctx, c.prefix+key).Err(); err != nil {
		c.redisFailed()
		return
	}
	c.redisSucceeded()
}

func (c *redisCache) redisAllowed() bool {
	c.stateMu.Lock()
	allowed := !time.Now().Before(c.retryAfter)
	c.stateMu.Unlock()
	return allowed
}

func (c *redisCache) redisFailed() {
	c.stateMu.Lock()
	wasClosed := c.retryAfter.IsZero()
	c.retryAfter = time.Now().Add(redisRetryDelay)
	c.stateMu.Unlock()
	if c.metrics != nil {
		c.metrics.inc(&c.metrics.redisError)
		if wasClosed {
			c.metrics.inc(&c.metrics.redisCircuit) // count each outage onset
		}
	}
}

func (c *redisCache) redisSucceeded() {
	c.stateMu.Lock()
	c.retryAfter = time.Time{}
	c.stateMu.Unlock()
}
