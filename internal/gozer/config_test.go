package gozer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEnvOrFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	if err := os.WriteFile(f, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FOO_FILE", f)
	t.Setenv("FOO", "from-env")
	if got := envOrFile("FOO"); got != "from-file" {
		t.Errorf("_FILE should win: got %q", got)
	}

	t.Setenv("FOO_FILE", "")
	if got := envOrFile("FOO"); got != "from-env" {
		t.Errorf("env fallback: got %q", got)
	}
}

func TestParseIdentityFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, IdentityFile)
	if err := os.WriteFile(f, []byte("user=alice\npass=s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, p := parseIdentityFile(f)
	if u != "alice" || p != "s3cr3t" {
		t.Errorf("parse: got user=%q pass=%q", u, p)
	}

	u, p = parseIdentityFile(filepath.Join(dir, "missing"))
	if u != "" || p != "" {
		t.Errorf("missing file should be empty: got %q/%q", u, p)
	}
}

func TestLoadIdentityPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, IdentityFile), []byte("user=file-u\npass=file-p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// env wins over the persisted file.
	t.Setenv("RAZOR_USER", "env-u")
	t.Setenv("RAZOR_PASS", "env-p")
	if u, p := loadIdentity(dir); u != "env-u" || p != "env-p" {
		t.Errorf("env should win: got %q/%q", u, p)
	}

	// with no env, fall back to the file.
	t.Setenv("RAZOR_USER", "")
	t.Setenv("RAZOR_PASS", "")
	if u, p := loadIdentity(dir); u != "file-u" || p != "file-p" {
		t.Errorf("file fallback: got %q/%q", u, p)
	}
}

func TestEnvDur(t *testing.T) {
	t.Setenv("T", "2.5")
	if got := envDur("T", 6); got != 2500*time.Millisecond {
		t.Errorf("envDur: got %s", got)
	}
	t.Setenv("T", "")
	if got := envDur("T", 6); got != 6*time.Second {
		t.Errorf("envDur default: got %s", got)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{
		"GOZER_HOST", "GOZER_PORT", "GOZER_BACKEND_TIMEOUT", "GOZER_MAX_CONCURRENT",
		"GOZER_TOKEN", "GOZER_TOKEN_FILE", "GOZER_CACHE_TTL", "GOZER_REDIS_URL",
		"RAZOR_USER", "RAZOR_PASS", "RAZORHOME", "DCCPROC",
	} {
		t.Setenv(k, "")
	}
	// point RAZORHOME at an empty dir so no stray identity file is found.
	t.Setenv("RAZORHOME", t.TempDir())

	c := LoadConfig()
	if c.Host != "0.0.0.0" || c.Port != 8077 {
		t.Errorf("host/port: %s:%d", c.Host, c.Port)
	}
	if c.BackendTimeout != 6*time.Second || c.MaxConcurrent != runtime.NumCPU() {
		t.Errorf("timeout/concurrency: %s/%d (want concurrency=%d)", c.BackendTimeout, c.MaxConcurrent, runtime.NumCPU())
	}
	if c.CacheTTL != 300*time.Second || c.MinCf != "ac" {
		t.Errorf("cache/mincf: %s/%s", c.CacheTTL, c.MinCf)
	}
	if c.DCCServers != "" || c.DCCClientID != 0 || c.DCCClientPass != "" {
		t.Errorf("dcc defaults: %q/%d/%q", c.DCCServers, c.DCCClientID, c.DCCClientPass)
	}
	if c.RazorUser != "" || c.RazorPass != "" {
		t.Errorf("identity should be empty: %q/%q", c.RazorUser, c.RazorPass)
	}
}
