// Package vocat is an authenticated HTTP client for vocat's own API.
//
// A vocat plugin backend receives no credentials: the reverse proxy in front of
// it strips the session cookie, the CSRF token and Authorization
// (internal/extensions/manager.go). So to act on its own — answering a call at
// 3am when no browser is open — this plugin has to hold admin credentials and
// log in like any other client.
//
// That is a real privilege escalation and the reason server-side mode is
// opt-in. Everything here is written to make the blast radius visible: one
// login per session lifetime, credentials never logged, and a hard refusal to
// talk to anything but loopback.
package vocat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrUnauthorized means the session was rejected and a fresh login is needed.
var ErrUnauthorized = errors.New("vocat: unauthorized")

// ErrRateLimited means vocat's login limiter is engaged. It carries the
// server's Retry-After so the caller can wait rather than making it worse.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (err ErrRateLimited) Error() string {
	return fmt.Sprintf("vocat: login rate limited, retry after %s", err.RetryAfter)
}

// Options configures the client.
type Options struct {
	// BaseURL is the vocat address. Only loopback is accepted, because these
	// credentials must never leave the machine.
	BaseURL  string
	Username string
	Password string
	// CertPath is vocat's self-signed certificate. When present it is pinned,
	// which is strictly better than skipping verification.
	CertPath string
	// InsecureSkipVerify is the fallback when the certificate file cannot be
	// read. Safe only because the target is pinned to loopback.
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Client holds one vocat session and refreshes it as needed.
type Client struct {
	base     *url.URL
	username string
	password string
	http     *http.Client

	mu        sync.Mutex
	csrf      string
	expiresAt time.Time
	// lockedUntil suppresses login attempts while vocat's limiter is engaged.
	// The limiter key is shared with the human admin on the same IP, so
	// hammering it would lock them out too.
	lockedUntil time.Time
}

// New builds a client. It does not log in; call Ensure for that.
func New(options Options) (*Client, error) {
	base, err := normalizeBase(options.BaseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.Username) == "" || options.Password == "" {
		return nil, errors.New("vocat: username and password are required")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	tlsConfig := &tls.Config{
		// websocket.Accept needs http.Hijacker, which HTTP/2 does not provide,
		// so the media socket only works over HTTP/1.1.
		NextProtos: []string{"http/1.1"},
	}
	if pem, readErr := os.ReadFile(options.CertPath); readErr == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(pem) {
			tlsConfig.RootCAs = pool
		} else if options.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		} else {
			return nil, errors.New("vocat: certificate file contains no usable certificate")
		}
	} else if options.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if strings.TrimSpace(options.CertPath) != "" {
		return nil, fmt.Errorf("vocat: read certificate: %w", readErr)
	} else {
		// No cert and no explicit opt-out: refuse rather than silently trusting
		// whatever answers on the port.
		return nil, errors.New("vocat: either cert_path or insecure_skip_verify is required for https")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("vocat: create cookie jar: %w", err)
	}
	return &Client{
		base:     base,
		username: options.Username,
		password: options.Password,
		http: &http.Client{
			Jar:     jar,
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:   tlsConfig,
				ForceAttemptHTTP2: false,
				DialContext:       (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			},
		},
	}, nil
}

// normalizeBase rejects any non-loopback target. Admin credentials for a remote
// host have no legitimate reason to live in a plugin's data directory.
func normalizeBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "https://127.0.0.1:7575"
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vocat: parse base URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("vocat: unsupported scheme %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errors.New("vocat: base URL has no host")
	}
	if host != "localhost" {
		address, parseErr := netipAddr(host)
		if parseErr != nil || !address.IsLoopback() {
			return nil, fmt.Errorf("vocat: base URL must be loopback, got %q", host)
		}
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed, nil
}

// HTTPClient exposes the configured client so a WebSocket dial can reuse the
// same cookie jar, pinned TLS and HTTP/1.1 setting.
func (client *Client) HTTPClient() *http.Client {
	return client.http
}

// BaseURL is the normalized vocat address.
func (client *Client) BaseURL() *url.URL {
	return client.base
}

// SessionValid reports whether a login is currently held and not near expiry.
func (client *Client) SessionValid() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.csrf != "" && time.Now().Add(5*time.Minute).Before(client.expiresAt)
}

// Ensure logs in when there is no usable session. vocat's session TTL is fixed
// at creation with no sliding window, so this re-logs in shortly before expiry
// rather than waiting for a 401 mid-call.
func (client *Client) Ensure(ctx context.Context) error {
	if client.SessionValid() {
		return nil
	}
	client.mu.Lock()
	if until := client.lockedUntil; time.Now().Before(until) {
		client.mu.Unlock()
		return ErrRateLimited{RetryAfter: time.Until(until)}
	}
	client.mu.Unlock()
	return client.login(ctx)
}

type loginResponse struct {
	Data struct {
		CSRFToken string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
	} `json:"data"`
}

func (client *Client) login(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{
		"username": client.username,
		"password": client.password,
	})
	if err != nil {
		return fmt.Errorf("vocat: encode login: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.base.String()+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vocat: build login request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("vocat: login: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusTooManyRequests {
		retry := parseRetryAfter(response.Header.Get("Retry-After"))
		client.mu.Lock()
		client.lockedUntil = time.Now().Add(retry)
		client.mu.Unlock()
		return ErrRateLimited{RetryAfter: retry}
	}
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: invalid credentials", ErrUnauthorized)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("vocat: login returned HTTP %d: %s",
			response.StatusCode, errorMessage(response.Body))
	}

	var decoded loginResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&decoded); err != nil {
		return fmt.Errorf("vocat: decode login response: %w", err)
	}
	if decoded.Data.CSRFToken == "" {
		return errors.New("vocat: login response carried no csrf token")
	}
	expiresAt, _ := time.Parse(time.RFC3339, decoded.Data.ExpiresAt)
	if expiresAt.IsZero() {
		// Fall back to the documented default so a missing field cannot make
		// the client believe the session never expires.
		expiresAt = time.Now().Add(24 * time.Hour)
	}
	client.mu.Lock()
	client.csrf = decoded.Data.CSRFToken
	client.expiresAt = expiresAt
	client.lockedUntil = time.Time{}
	client.mu.Unlock()
	return nil
}

// RefreshCSRF re-reads the session, which rotates the CSRF token without
// spending a bcrypt comparison. It does not extend the session.
func (client *Client) RefreshCSRF(ctx context.Context) error {
	var decoded loginResponse
	if err := client.do(ctx, http.MethodGet, "/api/auth/session", nil, &decoded); err != nil {
		return err
	}
	if decoded.Data.CSRFToken == "" {
		return errors.New("vocat: session response carried no csrf token")
	}
	expiresAt, _ := time.Parse(time.RFC3339, decoded.Data.ExpiresAt)
	client.mu.Lock()
	client.csrf = decoded.Data.CSRFToken
	if !expiresAt.IsZero() {
		client.expiresAt = expiresAt
	}
	client.mu.Unlock()
	return nil
}

// Get performs an authenticated GET and decodes the `data` envelope.
func (client *Client) Get(ctx context.Context, path string, out any) error {
	return client.authenticated(ctx, http.MethodGet, path, nil, out)
}

// Post performs an authenticated POST with the CSRF double-submit.
func (client *Client) Post(ctx context.Context, path string, body, out any) error {
	return client.authenticated(ctx, http.MethodPost, path, body, out)
}

// Delete performs an authenticated DELETE.
func (client *Client) Delete(ctx context.Context, path string, out any) error {
	return client.authenticated(ctx, http.MethodDelete, path, nil, out)
}

// authenticated ensures a session, then retries once on 401 because vocat
// clears both cookies on any auth failure and a revocation (password change,
// applied update) is indistinguishable from expiry.
func (client *Client) authenticated(ctx context.Context, method, path string, body, out any) error {
	if err := client.Ensure(ctx); err != nil {
		return err
	}
	err := client.do(ctx, method, path, body, out)
	if !errors.Is(err, ErrUnauthorized) {
		return err
	}
	client.mu.Lock()
	client.csrf = ""
	client.expiresAt = time.Time{}
	client.mu.Unlock()
	if loginErr := client.Ensure(ctx); loginErr != nil {
		return loginErr
	}
	return client.do(ctx, method, path, body, out)
}

func (client *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vocat: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.base.String()+path, reader)
	if err != nil {
		return fmt.Errorf("vocat: build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		client.mu.Lock()
		token := client.csrf
		client.mu.Unlock()
		if token == "" {
			return fmt.Errorf("%w: no csrf token held", ErrUnauthorized)
		}
		request.Header.Set("X-CSRF-Token", token)
	}

	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("vocat: %s %s: %w", method, path, err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s %s", ErrUnauthorized, method, path)
	case http.StatusForbidden:
		// A stale CSRF token is reported as 403 invalid_csrf. Treat it as an
		// auth problem so the caller re-logs in rather than giving up.
		message := errorMessage(response.Body)
		if strings.Contains(message, "csrf") || strings.Contains(message, "CSRF") {
			return fmt.Errorf("%w: %s", ErrUnauthorized, message)
		}
		return fmt.Errorf("vocat: %s %s: HTTP 403: %s", method, path, message)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("vocat: %s %s: HTTP %d: %s",
			method, path, response.StatusCode, errorMessage(response.Body))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("vocat: decode %s response: %w", path, err)
	}
	return nil
}

func errorMessage(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 4<<10))
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Error.Message != "" {
		if envelope.Error.Code != "" {
			return envelope.Error.Code + ": " + envelope.Error.Message
		}
		return envelope.Error.Message
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}

func parseRetryAfter(value string) time.Duration {
	seconds := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &seconds); err != nil || seconds <= 0 {
		return 10 * time.Minute
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return time.Duration(seconds) * time.Second
}
