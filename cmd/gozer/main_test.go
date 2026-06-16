package main

import "testing"

func TestRunRouting(t *testing.T) {
	if rc := run([]string{"version"}); rc != 0 {
		t.Errorf("version should exit 0, got %d", rc)
	}
	if rc := run([]string{"--version"}); rc != 0 {
		t.Errorf("--version should exit 0, got %d", rc)
	}
	if rc := run([]string{"bogus"}); rc != 2 {
		t.Errorf("unknown command should exit 2, got %d", rc)
	}
}

func TestRegisterBadFlag(t *testing.T) {
	if rc := run([]string{"razor-register", "--nope"}); rc != 2 {
		t.Errorf("bad flag should exit 2, got %d", rc)
	}
}
