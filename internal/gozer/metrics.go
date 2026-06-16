package gozer

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Metrics is gozer's hand-rolled Prometheus exposition (stdlib-only, no
// client_golang dependency) — the same shape the gdcc/gyzor/gazor sidecars use.
// It tracks per-endpoint request counters, cache hit/miss, busy rejections,
// per-backend errors and a request-latency histogram, and renders the text
// format at /metrics.
type Metrics struct {
	checkTotal     uint64
	reportTotal    uint64
	revokeTotal    uint64
	errorTotal     uint64 // request-level errors (busy, bad request)
	busyTotal      uint64
	cacheHit       uint64
	cacheMiss      uint64
	cacheCoalesced uint64
	redisError     uint64 // Redis L2 operation failures (fail-open)
	redisCircuit   uint64 // times the Redis circuit breaker opened

	backendErr struct {
		dcc   uint64
		razor uint64
		pyzor uint64
	}

	buckets []float64
	bcounts []uint64
	sumBits uint64
	count   uint64
}

// NewMetrics builds a Metrics with the standard latency buckets.
func NewMetrics() *Metrics {
	return &Metrics{
		buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		bcounts: make([]uint64, 11),
	}
}

func (m *Metrics) inc(p *uint64) {
	if m != nil {
		atomic.AddUint64(p, 1)
	}
}

// incPath bumps the per-endpoint request counter.
func (m *Metrics) incPath(path string) {
	if m == nil {
		return
	}
	switch path {
	case "/check":
		atomic.AddUint64(&m.checkTotal, 1)
	case "/report":
		atomic.AddUint64(&m.reportTotal, 1)
	case "/revoke":
		atomic.AddUint64(&m.revokeTotal, 1)
	}
}

// backendError bumps the per-backend error counter (dcc|razor|pyzor).
func (m *Metrics) backendError(backend string) {
	if m == nil {
		return
	}
	switch backend {
	case "dcc":
		atomic.AddUint64(&m.backendErr.dcc, 1)
	case "razor":
		atomic.AddUint64(&m.backendErr.razor, 1)
	case "pyzor":
		atomic.AddUint64(&m.backendErr.pyzor, 1)
	}
}

func (m *Metrics) observe(seconds float64) {
	if m == nil {
		return
	}
	for i, b := range m.buckets {
		if seconds <= b {
			atomic.AddUint64(&m.bcounts[i], 1)
			break
		}
	}
	atomicAddFloat64(&m.sumBits, seconds)
	atomic.AddUint64(&m.count, 1)
}

// ServeHTTP renders the Prometheus text exposition.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m.write(w)
}

func (m *Metrics) write(w io.Writer) {
	counter := func(name, help string, v uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("gozer_check_total", "Total /check requests.", atomic.LoadUint64(&m.checkTotal))
	counter("gozer_report_total", "Total /report requests.", atomic.LoadUint64(&m.reportTotal))
	counter("gozer_revoke_total", "Total /revoke requests.", atomic.LoadUint64(&m.revokeTotal))
	counter("gozer_error_total", "Total request-level errors.", atomic.LoadUint64(&m.errorTotal))
	counter("gozer_busy_total", "Requests rejected because max_concurrent was reached.", atomic.LoadUint64(&m.busyTotal))
	counter("gozer_cache_hit_total", "Verdict cache hits.", atomic.LoadUint64(&m.cacheHit))
	counter("gozer_cache_miss_total", "Verdict cache misses.", atomic.LoadUint64(&m.cacheMiss))
	counter("gozer_cache_coalesced_total", "Requests sharing an in-flight same-key cache miss.", atomic.LoadUint64(&m.cacheCoalesced))
	counter("gozer_redis_error_total", "Redis L2 operation failures (fail-open).", atomic.LoadUint64(&m.redisError))
	counter("gozer_redis_circuit_open_total", "Times the Redis circuit breaker opened.", atomic.LoadUint64(&m.redisCircuit))

	fmt.Fprint(w, "# HELP gozer_backend_error_total Backend errors by network.\n# TYPE gozer_backend_error_total counter\n")
	fmt.Fprintf(w, "gozer_backend_error_total{backend=\"dcc\"} %d\n", atomic.LoadUint64(&m.backendErr.dcc))
	fmt.Fprintf(w, "gozer_backend_error_total{backend=\"razor\"} %d\n", atomic.LoadUint64(&m.backendErr.razor))
	fmt.Fprintf(w, "gozer_backend_error_total{backend=\"pyzor\"} %d\n", atomic.LoadUint64(&m.backendErr.pyzor))

	fmt.Fprint(w, "# HELP gozer_latency_seconds Backend request latency.\n# TYPE gozer_latency_seconds histogram\n")
	var cumulative uint64
	for i, b := range m.buckets {
		cumulative += atomic.LoadUint64(&m.bcounts[i])
		fmt.Fprintf(w, "gozer_latency_seconds_bucket{le=\"%s\"} %d\n",
			strconv.FormatFloat(b, 'g', -1, 64), cumulative)
	}
	count := atomic.LoadUint64(&m.count)
	sum := math.Float64frombits(atomic.LoadUint64(&m.sumBits))
	fmt.Fprintf(w, "gozer_latency_seconds_bucket{le=\"+Inf\"} %d\n", count)
	fmt.Fprintf(w, "gozer_latency_seconds_sum %s\n", strconv.FormatFloat(sum, 'g', -1, 64))
	fmt.Fprintf(w, "gozer_latency_seconds_count %d\n", count)
}

// observeSince records a latency sample from a start time.
func (m *Metrics) observeSince(t time.Time) { m.observe(time.Since(t).Seconds()) }

func atomicAddFloat64(addr *uint64, delta float64) {
	for {
		old := atomic.LoadUint64(addr)
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if atomic.CompareAndSwapUint64(addr, old, next) {
			return
		}
	}
}
