package vocat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer stands in for vocat, implementing just enough of the login and
// CSRF contract to exercise the client.
func newTestServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var logins int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		var request struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Username != "admin" || request.Password != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"invalid_credentials","message":"nope"}}`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "vocat_session", Value: "session-token", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "vocat_csrf", Value: "csrf-token", Path: "/"})
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"csrf_token": "csrf-token",
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}})
	})
	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("vocat_session"); err != nil || cookie.Value != "session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"devices": []map[string]any{{
				"id": "ec20", "name": "Bench", "running": true,
				"modem": map[string]any{"iccid": "8944", "phone_number": "+447700900000"},
			}},
		}})
	})
	mux.HandleFunc("/api/devices/ec20/calls/answer", func(w http.ResponseWriter, r *http.Request) {
		// The double-submit contract: the header must match the cookie.
		cookie, err := r.Cookie("vocat_csrf")
		if err != nil || r.Header.Get("X-CSRF-Token") != cookie.Value {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"invalid_csrf","message":"CSRF validation failed"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"accepted": true, "call_id": "call-1",
			"call": map[string]any{"id": "call-1", "state": "active", "direction": "incoming"},
		}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &logins
}

func newTestClient(t *testing.T, base string) *Client {
	t.Helper()
	client, err := New(Options{
		BaseURL: base, Username: "admin", Password: "secret", InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func TestNewRejectsNonLoopbackTargets(t *testing.T) {
	// Admin credentials in a plugin data directory must never be aimed at a
	// remote host.
	for name, base := range map[string]string{
		"public host": "https://example.com:7575",
		"lan ip":      "https://192.168.1.10:7575",
		"public ip":   "https://93.184.216.34:7575",
		"bad scheme":  "ftp://127.0.0.1:7575",
	} {
		if _, err := New(Options{
			BaseURL: base, Username: "admin", Password: "secret", InsecureSkipVerify: true,
		}); err == nil {
			t.Fatalf("%s: New(%q) must fail", name, base)
		}
	}
	for _, base := range []string{"https://127.0.0.1:7575", "https://localhost:7575", "http://[::1]:7575"} {
		if _, err := New(Options{
			BaseURL: base, Username: "admin", Password: "secret", InsecureSkipVerify: true,
		}); err != nil {
			t.Fatalf("New(%q) error = %v", base, err)
		}
	}
}

func TestNewRequiresCredentialsAndACertificateDecision(t *testing.T) {
	if _, err := New(Options{BaseURL: "https://127.0.0.1:7575", InsecureSkipVerify: true}); err == nil {
		t.Fatal("New() must require a username and password")
	}
	// Neither a certificate nor an explicit opt-out: refuse rather than trusting
	// whatever answers on the port.
	if _, err := New(Options{
		BaseURL: "https://127.0.0.1:7575", Username: "admin", Password: "secret",
	}); err == nil {
		t.Fatal("New() must require cert_path or insecure_skip_verify")
	}
	// A configured but unreadable certificate is an error, not a silent
	// downgrade.
	if _, err := New(Options{
		BaseURL: "https://127.0.0.1:7575", Username: "admin", Password: "secret",
		CertPath: "/nonexistent/vocat.crt",
	}); err == nil {
		t.Fatal("New() must fail on an unreadable certificate")
	}
}

func TestLoginOncePerSession(t *testing.T) {
	server, logins := newTestServer(t)
	client := newTestClient(t, server.URL)
	ctx := context.Background()

	for index := 0; index < 3; index++ {
		if _, err := client.Devices(ctx); err != nil {
			t.Fatalf("Devices() call %d error = %v", index, err)
		}
	}
	// bcrypt cost 12 makes each login expensive, so a cached session matters.
	if got := atomic.LoadInt32(logins); got != 1 {
		t.Fatalf("login count = %d, want 1", got)
	}
	if !client.SessionValid() {
		t.Fatal("SessionValid() = false after a successful login")
	}
}

func TestBadCredentialsReportUnauthorized(t *testing.T) {
	server, _ := newTestServer(t)
	client, err := New(Options{
		BaseURL: server.URL, Username: "admin", Password: "wrong", InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := client.Ensure(context.Background()); err == nil {
		t.Fatal("Ensure() must fail with bad credentials")
	}
	if client.SessionValid() {
		t.Fatal("SessionValid() must be false after a failed login")
	}
}

func TestMutationSendsTheCSRFHeader(t *testing.T) {
	server, _ := newTestServer(t)
	client := newTestClient(t, server.URL)
	call, err := client.AnswerCall(context.Background(), "ec20", "call-1")
	if err != nil {
		t.Fatalf("AnswerCall() error = %v", err)
	}
	if call.ID != "call-1" || call.State != "active" {
		t.Fatalf("AnswerCall() = %+v", call)
	}
}

func TestRateLimitIsRespected(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	ctx := context.Background()
	var limited ErrRateLimited
	err := client.Ensure(ctx)
	if err == nil {
		t.Fatal("Ensure() must fail when rate limited")
	}
	if !asRateLimited(err, &limited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if limited.RetryAfter != 10*time.Minute {
		t.Fatalf("RetryAfter = %v, want 10m", limited.RetryAfter)
	}
	// A second attempt must not hit the server again: the limiter key is shared
	// with the human admin on the same IP, so hammering it would lock them out.
	if err := client.Ensure(ctx); err == nil {
		t.Fatal("Ensure() must keep failing while locked")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("login attempts = %d, want 1 while locked out", got)
	}
}

func TestReloginAfterSessionRevocation(t *testing.T) {
	// vocat revokes every session on a password change or applied update, and
	// clears both cookies on any 401. A 401 must therefore trigger a re-login,
	// not a hard failure.
	var logins, calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		http.SetCookie(w, &http.Cookie{Name: "vocat_session", Value: "s", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "vocat_csrf", Value: "c", Path: "/"})
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"csrf_token": "c",
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}})
	})
	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		// Reject the first request only, as a revoked session would.
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"devices": []map[string]any{{"id": "ec20"}},
		}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL)
	devices, err := client.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices() error = %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d", len(devices))
	}
	if got := atomic.LoadInt32(&logins); got != 2 {
		t.Fatalf("login count = %d, want 2 (initial plus re-login)", got)
	}
}

func TestMediaURLSchemeFollowsBase(t *testing.T) {
	secure := newTestClient(t, "https://127.0.0.1:7575")
	if got := secure.MediaURL("ec 20", "call/1"); !strings.HasPrefix(got, "wss://127.0.0.1:7575/") {
		t.Fatalf("MediaURL() = %q, want a wss URL", got)
	}
	plain := newTestClient(t, "http://127.0.0.1:7575")
	if got := plain.MediaURL("ec20", "c1"); !strings.HasPrefix(got, "ws://") {
		t.Fatalf("MediaURL() = %q, want a ws URL", got)
	}
	// Device ids and call ids must be escaped so a stray slash cannot change the
	// path.
	escaped := secure.MediaURL("ec 20", "call/1")
	if strings.Contains(escaped, "call/1") || !strings.Contains(escaped, "ec%2020") {
		t.Fatalf("MediaURL() did not escape its inputs: %q", escaped)
	}
}

func TestCallHelpers(t *testing.T) {
	ringing := Call{Direction: "incoming", State: "ringing"}
	if !ringing.Live() || !ringing.Ringing() {
		t.Fatalf("ringing call = %+v", ringing)
	}
	outgoing := Call{Direction: "outgoing", State: "ringing"}
	if outgoing.Ringing() {
		t.Fatal("an outgoing call must not report Ringing")
	}
	for _, state := range []string{"ended", "failed"} {
		if (Call{State: state}).Live() {
			t.Fatalf("state %q must not be live", state)
		}
	}
	for _, state := range []string{"dialing", "ringing", "early_media", "active"} {
		if !(Call{State: state}).Live() {
			t.Fatalf("state %q must be live", state)
		}
	}
}

func asRateLimited(err error, target *ErrRateLimited) bool {
	limited, ok := err.(ErrRateLimited)
	if ok {
		*target = limited
	}
	return ok
}
