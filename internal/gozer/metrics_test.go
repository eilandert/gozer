package gozer

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	srv := testServer(t, "tok", &fakeEngine{}, nil)

	// drive one /check and one /report so the counters move
	post(t, srv.URL, "/check", "tok", "From: a@b\r\n\r\nhi\r\n").Body.Close()
	post(t, srv.URL, "/report", "tok", "From: a@b\r\n\r\nhi\r\n").Body.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	for _, want := range []string{
		"gozer_check_total 1",
		"gozer_report_total 1",
		"gozer_cache_coalesced_total 0",
		"gozer_backend_error_total{backend=\"dcc\"}",
		"gozer_latency_seconds_count 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
}

func TestMetricsNilSafe(t *testing.T) {
	var m *Metrics
	// all helpers must be no-ops on a nil receiver
	m.inc(nil)
	m.incPath("/check")
	m.backendError("dcc")
	m.observe(0.1)
}

func TestParsePyzorServers(t *testing.T) {
	if parsePyzorServers("") != nil {
		t.Error("empty -> nil")
	}
	got := parsePyzorServers("a.example, b.example:1234 ,[::1]:24441")
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Host != "a.example" || got[0].Port != 24441 {
		t.Errorf("default port: %+v", got[0])
	}
	if got[1].Host != "b.example" || got[1].Port != 1234 {
		t.Errorf("explicit port: %+v", got[1])
	}
	if got[2].Host != "::1" || got[2].Port != 24441 {
		t.Errorf("ipv6: %+v", got[2])
	}
}

func TestSplitCommaList(t *testing.T) {
	if splitCommaList("  ") != nil {
		t.Error("blank -> nil")
	}
	got := splitCommaList("d1, d2 ,d3")
	if len(got) != 3 || got[0] != "d1" || got[2] != "d3" {
		t.Errorf("got %v", got)
	}
}
