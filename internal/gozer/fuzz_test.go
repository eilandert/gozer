package gozer

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzServe drives gozer's HTTP front-end — auth, the body-size limit, the
// Content-Length validation, routing, the bounded-concurrency gate and dispatch
// — with an arbitrary method, path, token header and request body. The backend
// is a no-network fakeEngine, so this fuzzes only gozer's own request handling,
// not the live DCC/Razor/Pyzor networks.
//
// Invariant: ServeHTTP must never panic and must always answer with a valid
// HTTP status code, whatever bytes an attacker puts on the wire.
func FuzzServe(f *testing.F) {
	f.Add("POST", "/check", "secret", true, []byte("Subject: x\n\nhi\n"))
	f.Add("GET", "/health", "", false, []byte(nil))
	f.Add("GET", "/metrics", "", false, []byte(nil))
	f.Add("POST", "/report", "secret", false, []byte("x"))
	f.Add("POST", "/revoke", "wrong", true, []byte{0x00, 0xff, 0xfe})
	f.Add("PUT", "/check", "secret", true, []byte("method not allowed"))
	f.Add("POST", "/check", "", true, make([]byte, 9000)) // over MaxBody → 413

	const token = "secret"
	cfg := &Config{Token: token, MaxConcurrent: 4, BackendTimeout: time.Second, MaxBody: 4096}
	h := NewServerWithEngine(cfg, &fakeEngine{}, nil)

	f.Fuzz(func(t *testing.T, method, path, tok string, bearer bool, body []byte) {
		// http.NewRequest validates the method token and the URL; a malformed
		// value is a net/http limitation, not a gozer bug, so skip those
		// iterations and keep the fuzzer aimed at our handler.
		req, err := http.NewRequest(method, "http://gozer.test"+path, bytes.NewReader(body))
		if err != nil {
			return
		}
		if tok != "" {
			if bearer {
				req.Header.Set("Authorization", "Bearer "+tok)
			} else {
				req.Header.Set("X-DRP-Token", tok)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req) // must not panic
		if rec.Code < 100 || rec.Code > 599 {
			t.Fatalf("invalid HTTP status %d for %q %q", rec.Code, method, path)
		}
	})
}

// FuzzParsePyzorServers fuzzes the GYZOR_SERVERS / --pyzor-servers parser, which
// turns an operator-supplied "host:port,host" string into pyzor.Server entries.
// The value is config, but it is still untrusted text worth hardening.
//
// Invariant: never panics and is deterministic (same input → same result).
func FuzzParsePyzorServers(f *testing.F) {
	f.Add("public.pyzor.org:24441")
	f.Add("a, b:1 ,c:24441,[::1]:24441")
	f.Add("")
	f.Add(",,, : :: host: :99999")
	f.Fuzz(func(t *testing.T, spec string) {
		got := parsePyzorServers(spec)  // must not panic
		got2 := parsePyzorServers(spec) // must be deterministic
		if len(got) != len(got2) {
			t.Fatalf("nondeterministic parse for %q: %d vs %d", spec, len(got), len(got2))
		}
	})
}
