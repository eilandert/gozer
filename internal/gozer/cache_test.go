package gozer

import (
	"testing"
	"time"
)

func TestMemCacheHitMiss(t *testing.T) {
	c := newMemCache(16, time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("empty cache should miss")
	}
	c.Put("k", []byte("v"))
	v, ok := c.Get("k")
	if !ok || string(v) != "v" {
		t.Fatalf("expected hit v, got %q ok=%v", v, ok)
	}
}

func TestMemCacheExpiry(t *testing.T) {
	c := newMemCache(16, 20*time.Millisecond)
	c.Put("k", []byte("v"))
	time.Sleep(40 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry should have expired")
	}
}

func TestMemCacheEviction(t *testing.T) {
	c := newMemCache(2, time.Minute)
	c.Put("a", []byte("1"))
	c.Put("b", []byte("2"))
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected a hit")
	}
	c.Put("c", []byte("3")) // forces eviction back under cap of 2

	if len(c.d) > 2 {
		t.Fatalf("cache exceeded cap: %d entries", len(c.d))
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("newest entry c should survive")
	}
	if _, ok := c.Get("b"); ok {
		t.Error("least-recently-used entry b should have been evicted")
	}
}

func TestMemCacheRefreshAtCapacity(t *testing.T) {
	c := newMemCache(2, time.Minute)
	c.Put("a", []byte("1"))
	c.Put("b", []byte("2"))
	c.Put("b", []byte("updated"))
	if _, ok := c.Get("a"); !ok {
		t.Error("refreshing b must not evict a")
	}
	if got, ok := c.Get("b"); !ok || string(got) != "updated" {
		t.Errorf("refreshed b = %q, %t", got, ok)
	}
}

func TestNewCacheDisabled(t *testing.T) {
	cfg := &Config{CacheTTL: 0}
	if NewCache(cfg, func(string, ...any) {}, nil) != nil {
		t.Fatal("TTL<=0 must disable caching")
	}
}

func TestNewCacheMemory(t *testing.T) {
	cfg := &Config{CacheTTL: time.Minute, CacheSize: 8}
	c := NewCache(cfg, func(string, ...any) {}, nil)
	if _, ok := c.(*memCache); !ok {
		t.Fatalf("expected *memCache, got %T", c)
	}
}
