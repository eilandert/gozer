package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// wrote. The register handlers print directly to os.Stdout.
func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	rc := fn()
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return rc, string(out)
}

func TestPyzorRegisterCLI(t *testing.T) {
	home := t.TempDir()
	rc, out := captureStdout(t, func() int {
		return run([]string{"pyzor-register", "--user", "alice", "--home", home, "--servers", "h.example:24441"})
	})
	if rc != 0 {
		t.Fatalf("rc=%d out=%q", rc, out)
	}
	for _, want := range []string{"saved account to", "GYZOR_USER=alice", "GYZOR_KEY=", "GYZOR_SALT="} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %q", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "accounts")); err != nil {
		t.Fatalf("accounts file not written: %v", err)
	}
}

func TestPyzorRegisterCLIRequiresUser(t *testing.T) {
	if rc := run([]string{"pyzor-register", "--home", t.TempDir()}); rc != 2 {
		t.Errorf("missing --user should exit 2, got %d", rc)
	}
}

func TestDCCRegisterCLI(t *testing.T) {
	ids := filepath.Join(t.TempDir(), "ids")
	rc, out := captureStdout(t, func() int {
		return run([]string{"dcc-register", "--client-id", "32", "--passwd", "s3cret", "--out", ids})
	})
	if rc != 0 {
		t.Fatalf("rc=%d out=%q", rc, out)
	}
	for _, want := range []string{"saved client-id 32", "DCC_CLIENT_ID=32", "DCC_CLIENT_PASSWD=s3cret"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %q", want, out)
		}
	}
	data, _ := os.ReadFile(ids)
	if !strings.Contains(string(data), "32 s3cret") {
		t.Fatalf("ids entry missing: %q", data)
	}
}

func TestDCCRegisterCLIValidation(t *testing.T) {
	ids := filepath.Join(t.TempDir(), "ids")
	// Anonymous/missing id and missing password are usage errors.
	if rc := run([]string{"dcc-register", "--passwd", "p", "--out", ids}); rc != 2 {
		t.Errorf("missing id should exit 2, got %d", rc)
	}
	if rc := run([]string{"dcc-register", "--client-id", "32", "--out", ids}); rc != 2 {
		t.Errorf("missing passwd should exit 2, got %d", rc)
	}
}
