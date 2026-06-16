package gozer

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkMemCacheHit(b *testing.B) {
	c := newMemCache(4096, 5*time.Minute)
	c.Put("key", []byte(`{"cached":true}`))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get("key"); !ok {
			b.Fatal("unexpected miss")
		}
	}
}

func BenchmarkMemCachePutAtCapacity(b *testing.B) {
	c := newMemCache(4096, 5*time.Minute)
	for i := 0; i < c.size; i++ {
		c.Put(strconv.Itoa(i), []byte(`{"cached":true}`))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Put("new-"+strconv.Itoa(i), []byte(`{"cached":true}`))
	}
}
