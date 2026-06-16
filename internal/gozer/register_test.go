package gozer

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestPyzorRegisterGenerates(t *testing.T) {
	home := t.TempDir()
	path, acc, generated, err := PyzorRegister(home, "h.example:24441", "alice", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Fatal("expected generated=true when key empty")
	}
	if !hex40.MatchString(acc.Salt) || !hex40.MatchString(acc.Key) {
		t.Fatalf("salt/key not 40-hex: %q,%q", acc.Salt, acc.Key)
	}
	if path != filepath.Join(home, "accounts") {
		t.Fatalf("path = %s", path)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "h.example : 24441 : alice :") {
		t.Fatalf("accounts entry missing: %q", data)
	}
}

func TestPyzorRegisterSplitsCombinedKey(t *testing.T) {
	home := t.TempDir()
	_, acc, generated, err := PyzorRegister(home, "h.example:24441", "alice", "ssss,kkkk", "")
	if err != nil {
		t.Fatal(err)
	}
	if generated {
		t.Fatal("expected generated=false when key supplied")
	}
	if acc.Salt != "ssss" || acc.Key != "kkkk" {
		t.Fatalf("combined salt,key not split: %+v", acc)
	}
}

func TestPyzorRegisterRequiresUser(t *testing.T) {
	if _, _, _, err := PyzorRegister(t.TempDir(), "", "", "", ""); err == nil {
		t.Fatal("expected error for empty user")
	}
}

func TestDCCRegister(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids")
	if err := DCCRegister(path, 32, "pw"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "32 pw") {
		t.Fatalf("ids entry missing: %q", data)
	}
	// Anonymous id is rejected by the gdcc validator.
	if err := DCCRegister(path, 1, "x"); err == nil {
		t.Fatal("expected error for anonymous id")
	}
}
