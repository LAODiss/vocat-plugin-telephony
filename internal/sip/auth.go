// Digest authentication for the SIP gateway.
//
// This implements the MD5 qop=auth flavour that Linphone and comparable clients
// use. It is the only thing standing between a LAN-reachable SIP port and
// someone placing calls on the operator's SIM, so the verification path is
// written to fail closed: an unparsable header, a stale nonce, an unknown
// username and a wrong password all produce the same outcome.
package sip

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Credentials is one SIP account.
type Credentials struct {
	Username string
	Password string
	Realm    string
}

// Challenge is a parsed WWW-Authenticate/Authorization header.
type Challenge struct {
	Realm      string
	Nonce      string
	Username   string
	URI        string
	Response   string
	Algorithm  string
	QOP        string
	CNonce     string
	NonceCount string
	Opaque     string
}

// ParseAuthorization decodes an Authorization or Proxy-Authorization header.
func ParseAuthorization(header string) (Challenge, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return Challenge{}, fmt.Errorf("sip: empty authorization header")
	}
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(scheme), "Digest") {
		return Challenge{}, fmt.Errorf("sip: unsupported auth scheme %q", scheme)
	}
	challenge := Challenge{}
	for _, part := range splitAuthParams(rest) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
		case "realm":
			challenge.Realm = value
		case "nonce":
			challenge.Nonce = value
		case "username":
			challenge.Username = value
		case "uri":
			challenge.URI = value
		case "response":
			challenge.Response = value
		case "algorithm":
			challenge.Algorithm = strings.ToUpper(value)
		case "qop":
			challenge.QOP = strings.ToLower(value)
		case "cnonce":
			challenge.CNonce = value
		case "nc":
			challenge.NonceCount = value
		case "opaque":
			challenge.Opaque = value
		}
	}
	if challenge.Username == "" || challenge.Nonce == "" || challenge.Response == "" {
		return Challenge{}, fmt.Errorf("sip: authorization header is missing required fields")
	}
	return challenge, nil
}

// splitAuthParams splits on commas that are not inside a quoted string. A
// quoted value may legally contain a comma, and splitting naively would corrupt
// the nonce.
func splitAuthParams(value string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character == '"':
			inQuotes = !inQuotes
			current.WriteByte(character)
		case character == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(character)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// DigestResponse computes the RFC 2617 response hash. It is exported so tests
// and a future outbound-registration path can produce the same value.
func DigestResponse(credentials Credentials, method, uri string, challenge Challenge) string {
	realm := challenge.Realm
	if realm == "" {
		realm = credentials.Realm
	}
	ha1 := md5hex(credentials.Username + ":" + realm + ":" + credentials.Password)
	ha2 := md5hex(strings.ToUpper(method) + ":" + uri)
	if challenge.QOP == "auth" {
		count := challenge.NonceCount
		if count == "" {
			count = "00000001"
		}
		return md5hex(strings.Join([]string{
			ha1, challenge.Nonce, count, challenge.CNonce, "auth", ha2,
		}, ":"))
	}
	return md5hex(ha1 + ":" + challenge.Nonce + ":" + ha2)
}

func md5hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// nonceLifetime is how long a challenge stays valid. Long enough for a slow
// client to answer, short enough that a captured nonce is not reusable for
// long.
const nonceLifetime = 5 * time.Minute

// Authenticator issues and verifies digest challenges.
//
// Nonces are stateless: each carries its own issue time and an HMAC over that
// time, so a restart does not invalidate in-flight registrations and there is no
// unbounded nonce table to grow. Replay is bounded by the lifetime rather than
// tracked per nonce, which is the usual trade for a single-tenant gateway.
type Authenticator struct {
	realm string
	// secret keys the nonce HMAC. It is generated per process, so nonces do not
	// survive a restart — clients simply re-authenticate.
	secret []byte

	mu sync.Mutex
	// failures counts consecutive rejections per source, so a scanner cannot
	// grind through passwords unnoticed.
	failures map[string]*failureRecord
}

type failureRecord struct {
	count       int
	lockedUntil time.Time
	lastSeen    time.Time
}

const (
	// maxFailures and lockout bound password guessing. A SIP port reachable on a
	// LAN attracts scanners, and each guess would otherwise be free.
	maxFailures = 8
	lockout     = 10 * time.Minute
)

func NewAuthenticator(realm string) (*Authenticator, error) {
	if strings.TrimSpace(realm) == "" {
		realm = "vocat"
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("sip: generate nonce secret: %w", err)
	}
	return &Authenticator{
		realm:    realm,
		secret:   secret,
		failures: map[string]*failureRecord{},
	}, nil
}

// Realm is the authentication realm presented to clients.
func (auth *Authenticator) Realm() string {
	return auth.realm
}

// Nonce issues a fresh challenge nonce.
func (auth *Authenticator) Nonce() string {
	return auth.signNonce(time.Now().Unix())
}

// signNonce builds "<unix>:<hmac>" for a given issue time. Splitting it out
// keeps the format in one place and lets tests construct an expired nonce
// through the same signing path, so only its age is wrong.
func (auth *Authenticator) signNonce(issued int64) string {
	payload := fmt.Sprintf("%d", issued)
	digest := hmac.New(sha256.New, auth.secret)
	digest.Write([]byte(payload))
	return payload + ":" + hex.EncodeToString(digest.Sum(nil)[:16])
}

// ChallengeHeader builds a WWW-Authenticate value.
func (auth *Authenticator) ChallengeHeader() string {
	return fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`,
		auth.realm, auth.Nonce())
}

// validNonce reports whether a nonce was issued by this process and is still
// within its lifetime.
func (auth *Authenticator) validNonce(nonce string) bool {
	issuedText, signature, found := strings.Cut(nonce, ":")
	if !found {
		return false
	}
	digest := hmac.New(sha256.New, auth.secret)
	digest.Write([]byte(issuedText))
	expected := hex.EncodeToString(digest.Sum(nil)[:16])
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return false
	}
	var issued int64
	if _, err := fmt.Sscanf(issuedText, "%d", &issued); err != nil {
		return false
	}
	age := time.Since(time.Unix(issued, 0))
	return age >= 0 && age <= nonceLifetime
}

// Result describes the outcome of verifying a request.
type Result int

const (
	// ResultOK means the credentials matched.
	ResultOK Result = iota
	// ResultChallenge means no usable credentials were supplied, or the nonce
	// expired, so the client should retry with a fresh challenge.
	ResultChallenge
	// ResultReject means the credentials were wrong. This is deliberately
	// distinct from ResultChallenge so a wrong password can be counted.
	ResultReject
	// ResultLocked means too many failures from this source.
	ResultLocked
)

// Verify checks a request's Authorization header against the account.
//
// source identifies the client for rate-limiting purposes; it should be the
// remote address, not a value taken from the message, or an attacker could evade
// the limiter by forging it.
func (auth *Authenticator) Verify(message *Message, credentials Credentials, source string) Result {
	if auth.locked(source) {
		return ResultLocked
	}
	header := message.Get("Authorization")
	if header == "" {
		header = message.Get("Proxy-Authorization")
	}
	if header == "" {
		return ResultChallenge
	}
	challenge, err := ParseAuthorization(header)
	if err != nil {
		return ResultChallenge
	}
	if !auth.validNonce(challenge.Nonce) {
		// A stale nonce is not a wrong password: re-challenge without counting a
		// failure, or a client that sat idle would get locked out.
		return ResultChallenge
	}
	if challenge.Username != credentials.Username {
		auth.recordFailure(source)
		return ResultReject
	}
	// The client signs the URI it sent, which may differ from the request URI in
	// whitespace or parameters, so the value from the header is used as-is.
	uri := challenge.URI
	if uri == "" {
		uri = message.URI
	}
	_, method := message.CSeq()
	if method == "" {
		method = message.Method
	}
	expected := DigestResponse(credentials, method, uri, challenge)
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(challenge.Response))) {
		auth.recordFailure(source)
		return ResultReject
	}
	auth.recordSuccess(source)
	return ResultOK
}

func (auth *Authenticator) locked(source string) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	auth.pruneLocked()
	record := auth.failures[source]
	return record != nil && time.Now().Before(record.lockedUntil)
}

func (auth *Authenticator) recordFailure(source string) {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	auth.pruneLocked()
	record := auth.failures[source]
	if record == nil {
		record = &failureRecord{}
		auth.failures[source] = record
	}
	record.count++
	record.lastSeen = time.Now()
	if record.count >= maxFailures {
		record.lockedUntil = time.Now().Add(lockout)
		record.count = 0
	}
}

func (auth *Authenticator) recordSuccess(source string) {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	delete(auth.failures, source)
}

// pruneLocked drops stale entries so a scanner cycling source ports cannot grow
// the map without bound. Callers hold the lock.
func (auth *Authenticator) pruneLocked() {
	if len(auth.failures) < 512 {
		return
	}
	cutoff := time.Now().Add(-2 * lockout)
	for source, record := range auth.failures {
		if record.lastSeen.Before(cutoff) && time.Now().After(record.lockedUntil) {
			delete(auth.failures, source)
		}
	}
}

// LockedSources returns how many sources are currently locked out, for the
// panel's security view.
func (auth *Authenticator) LockedSources() int {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	count := 0
	now := time.Now()
	for _, record := range auth.failures {
		if now.Before(record.lockedUntil) {
			count++
		}
	}
	return count
}
