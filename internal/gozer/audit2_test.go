package gozer

import (
	"runtime"
	"testing"
	"time"
)

// TestReportInvalidatesCache: a /check verdict cached, then a /report or
// /revoke of the same message must drop the stale entry so the next /check
// re-queries the backends.
func TestReportInvalidatesCache(t *testing.T) {
	for _, feedback := range []string{"/report", "/revoke"} {
		eng := &fakeEngine{}
		cache := newMemCache(8, time.Minute)
		srv := testServer(t, "tok", eng, cache)

		post(t, srv.URL, "/check", "tok", "same-body").Body.Close() // miss -> cached
		post(t, srv.URL, "/check", "tok", "same-body").Body.Close() // hit
		if got := eng.checks.Load(); got != 1 {
			t.Fatalf("%s: expected 1 check before feedback, got %d", feedback, got)
		}

		post(t, srv.URL, feedback, "tok", "same-body").Body.Close() // invalidates

		post(t, srv.URL, "/check", "tok", "same-body").Body.Close() // must re-run
		if got := eng.checks.Load(); got != 2 {
			t.Errorf("%s did not invalidate cache: checks=%d, want 2", feedback, got)
		}
	}
}

func TestSanitizeClampsInvalidConfig(t *testing.T) {
	c := &Config{MaxConcurrent: 0, Port: 0, BackendTimeout: 0, MaxBody: 0, CacheSize: -1, CacheTTL: -1}
	c.sanitize()
	if c.MaxConcurrent != runtime.NumCPU() {
		t.Errorf("MaxConcurrent = %d, want %d", c.MaxConcurrent, runtime.NumCPU())
	}
	if c.Port != 8077 {
		t.Errorf("Port = %d, want 8077", c.Port)
	}
	if c.BackendTimeout != 6*time.Second {
		t.Errorf("BackendTimeout = %s, want 6s", c.BackendTimeout)
	}
	if c.MaxBody != 8*1024*1024 {
		t.Errorf("MaxBody = %d", c.MaxBody)
	}
	if c.CacheSize != 4096 {
		t.Errorf("CacheSize = %d, want 4096", c.CacheSize)
	}
	if c.CacheTTL != 0 {
		t.Errorf("CacheTTL = %s, want 0", c.CacheTTL)
	}
}

func TestSanitizeNegativeConcurrencyDoesNotPanic(t *testing.T) {
	// make(chan, negative) would panic; NewServer must sanitize first.
	cfg := &Config{MaxConcurrent: -5, Port: 8077, BackendTimeout: time.Second, MaxBody: 1024}
	_ = NewServerWithEngine(cfg, &fakeEngine{}, nil) // would panic if unclamped
	if cfg.MaxConcurrent != runtime.NumCPU() {
		t.Errorf("MaxConcurrent not clamped: %d, want %d", cfg.MaxConcurrent, runtime.NumCPU())
	}
}

func TestMemCacheDelete(t *testing.T) {
	c := newMemCache(8, time.Minute)
	c.Put("k", []byte("v"))
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected hit")
	}
	c.Delete("k")
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss after delete")
	}
}
