package gozer

import (
	"bytes"
	"context"
	"net/url"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisPromotionPreservesRemainingTTL(t *testing.T) {
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	socket := filepath.Join(t.TempDir(), "redis.sock")
	cmd := exec.Command(bin,
		"--save", "",
		"--appendonly", "no",
		"--port", "0",
		"--unixsocket", socket,
		"--unixsocketperm", "700",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("start redis-server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	redisURL := (&url.URL{Scheme: "unix", Path: socket}).String()
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	probe := redis.NewClient(opt)
	t.Cleanup(func() { _ = probe.Close() })
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := probe.Ping(ctx).Err(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("redis-server did not become ready: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	const redisTTL = 600 * time.Millisecond
	cfg := &Config{RedisURL: redisURL, RedisPrefix: "test:", CacheTTL: time.Second}
	l1 := newMemCache(8, cfg.CacheTTL)
	cache, err := newRedisCache(cfg, l1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.rdb.Close() })
	if err := cache.rdb.Set(ctx, cfg.RedisPrefix+"key", []byte("value"), redisTTL).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	if got, ok := cache.Get("key"); !ok || string(got) != "value" {
		t.Fatalf("Redis promotion = %q, %t", got, ok)
	}
	l1.mu.Lock()
	remaining := time.Until(l1.d["key"].exp)
	l1.mu.Unlock()
	if remaining <= 0 || remaining >= 500*time.Millisecond {
		t.Fatalf("L1 TTL = %s; expected Redis remaining TTL, not a fresh %s", remaining, cfg.CacheTTL)
	}
}
