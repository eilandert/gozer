package gozer

import (
	"sync/atomic"
	"testing"
)

// TestRedisFailureMetrics: a Redis failure increments gozer_redis_error_total,
// and the first failure after a closed circuit also increments
// gozer_redis_circuit_open_total (subsequent failures while open do not).
func TestRedisFailureMetrics(t *testing.T) {
	m := NewMetrics()
	c := &redisCache{metrics: m}

	c.redisFailed() // outage onset: error + circuit open
	c.redisFailed() // still open: error only

	if got := atomic.LoadUint64(&m.redisError); got != 2 {
		t.Errorf("redisError = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&m.redisCircuit); got != 1 {
		t.Errorf("redisCircuit = %d, want 1 (one onset)", got)
	}

	c.redisSucceeded() // closes the circuit
	c.redisFailed()    // new onset: circuit opens again
	if got := atomic.LoadUint64(&m.redisCircuit); got != 2 {
		t.Errorf("redisCircuit = %d, want 2 after re-open", got)
	}

	// nil metrics must be a no-op, not a panic
	(&redisCache{}).redisFailed()
}
