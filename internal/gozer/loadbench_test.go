package gozer

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// latencyEngine simulates the three networks with a fixed per-check latency so
// the benchmark measures gozer's request path, cache, single-flight and
// concurrency gate under realistic backend RTT. It counts backend executions so
// the test can confirm the cache/coalescing actually offloaded work.
type latencyEngine struct {
	delay time.Duration
	calls atomic.Int64
}

func (e *latencyEngine) Check(msg []byte) (Verdict, bool) {
	e.calls.Add(1)
	time.Sleep(e.delay)
	n := 3
	return Verdict{DCC: DCCResult{Action: "accept"}, Pyzor: PyzorResult{Count: n}}, true
}
func (e *latencyEngine) Report(msg []byte) ReportResult { return ReportResult{} }
func (e *latencyEngine) Revoke(msg []byte) ReportResult { return ReportResult{} }
func (e *latencyEngine) HasRazorIdentity() bool         { return true }

// benchServe drives /check through the full server (auth, gate, cache,
// single-flight, dispatch) with a hitRatio fraction of requests hitting a small
// set of repeated bodies (cache hits) and the rest unique (misses → backend).
func benchServe(b *testing.B, maxConc int, backendDelay time.Duration, hitRatio float64) {
	eng := &latencyEngine{delay: backendDelay}
	cfg := &Config{
		Host: "127.0.0.1", Port: 8077, Token: "t", MaxConcurrent: maxConc,
		BackendTimeout: 5 * time.Second, MaxBody: 1 << 20,
		CacheTTL: time.Minute, CacheSize: 4096,
	}
	cache := newMemCache(cfg.CacheSize, cfg.CacheTTL)
	srv := NewServerWithEngine(cfg, eng, cache)

	// pre-seed a small hot set so hitRatio of requests are cache hits
	const hotN = 64
	hot := make([][]byte, hotN)
	for i := range hot {
		hot[i] = []byte(fmt.Sprintf("From: a@b\r\nMessage-ID: <hot-%d>\r\n\r\nhot body number %d here today\r\n", i, i))
		// warm the cache
		w := &respRecorder{}
		srv.ServeHTTP(w, mustPost(hot[i]))
	}

	b.ResetTimer()
	b.ReportAllocs()
	var uniq atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var body []byte
			if randFloat() < hitRatio {
				body = hot[uniq.Add(1)%hotN]
			} else {
				body = []byte(fmt.Sprintf("From: a@b\r\nMessage-ID: <u-%d>\r\n\r\nunique body %d\r\n", uniq.Add(1), uniq.Load()))
			}
			w := &respRecorder{}
			srv.ServeHTTP(w, mustPost(body))
			if w.code != http.StatusOK {
				b.Fatalf("status %d", w.code)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "msg/s")
	b.ReportMetric(float64(eng.calls.Load())/float64(b.N), "backend-calls/op")
}

func BenchmarkServe90PctCacheHit(b *testing.B) { benchServe(b, 8, 2*time.Millisecond, 0.90) }
func BenchmarkServe50PctCacheHit(b *testing.B) { benchServe(b, 16, 2*time.Millisecond, 0.50) }
func BenchmarkServeAllMiss(b *testing.B)       { benchServe(b, 32, 2*time.Millisecond, 0.0) }

// --- tiny helpers (avoid httptest overhead in the hot loop) ---

type respRecorder struct {
	code int
	hdr  http.Header
}

func (r *respRecorder) Header() http.Header {
	if r.hdr == nil {
		r.hdr = http.Header{}
	}
	return r.hdr
}
func (r *respRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *respRecorder) WriteHeader(c int)           { r.code = c }

func mustPost(body []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/check", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer t")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body))) // handlePost reads the header
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	return req
}

// randFloat is a cheap xorshift-based [0,1) source (no crypto needed for a bench).
var randState atomic.Uint64

func randFloat() float64 {
	x := randState.Add(0x9E3779B97F4A7C15)
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	return float64(x>>11) / float64(1<<53)
}
