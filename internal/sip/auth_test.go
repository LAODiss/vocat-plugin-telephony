package sip

import (
	"strings"
	"testing"
	"time"
)

func testCredentials() Credentials {
	return Credentials{Username: "alice", Password: "s3cret", Realm: "vocat"}
}

// authorizedRegister builds a REGISTER carrying a correct digest response for
// the given challenge, the way a client would.
func authorizedRegister(t *testing.T, auth *Authenticator, credentials Credentials, nonce string) *Message {
	t.Helper()
	uri := "sip:vocat.local"
	challenge := Challenge{
		Realm: auth.Realm(), Nonce: nonce, Username: credentials.Username,
		URI: uri, QOP: "auth", CNonce: "cnonce1", NonceCount: "00000001",
	}
	challenge.Response = DigestResponse(credentials, "REGISTER", uri, challenge)
	header := `Digest username="` + challenge.Username + `", realm="` + challenge.Realm +
		`", nonce="` + challenge.Nonce + `", uri="` + uri +
		`", response="` + challenge.Response + `", qop=auth, nc=00000001, cnonce="cnonce1"`

	message, err := Parse([]byte("REGISTER " + uri + " SIP/2.0\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Authorization: " + header + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return message
}

func TestVerifyAcceptsCorrectCredentials(t *testing.T) {
	auth, err := NewAuthenticator("vocat")
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	message := authorizedRegister(t, auth, testCredentials(), auth.Nonce())
	if got := auth.Verify(message, testCredentials(), "192.168.1.50:5060"); got != ResultOK {
		t.Fatalf("Verify() = %v, want ResultOK", got)
	}
}

func TestVerifyChallengesWhenNoCredentialsSupplied(t *testing.T) {
	auth, _ := NewAuthenticator("vocat")
	message, _ := Parse([]byte("REGISTER sip:vocat.local SIP/2.0\r\nCSeq: 1 REGISTER\r\n\r\n"))
	if got := auth.Verify(message, testCredentials(), "1.2.3.4:5060"); got != ResultChallenge {
		t.Fatalf("Verify() = %v, want ResultChallenge", got)
	}
}

func TestVerifyRejectsWrongPasswordAndUsername(t *testing.T) {
	auth, _ := NewAuthenticator("vocat")
	nonce := auth.Nonce()

	// Right username, wrong password: the client computed its response with a
	// different secret.
	wrongPassword := authorizedRegister(t, auth, Credentials{
		Username: "alice", Password: "wrong", Realm: "vocat",
	}, nonce)
	if got := auth.Verify(wrongPassword, testCredentials(), "1.2.3.4:5060"); got != ResultReject {
		t.Fatalf("wrong password: Verify() = %v, want ResultReject", got)
	}

	wrongUser := authorizedRegister(t, auth, Credentials{
		Username: "bob", Password: "s3cret", Realm: "vocat",
	}, nonce)
	if got := auth.Verify(wrongUser, testCredentials(), "5.6.7.8:5060"); got != ResultReject {
		t.Fatalf("wrong username: Verify() = %v, want ResultReject", got)
	}
}

func TestVerifyRejectsForeignNonce(t *testing.T) {
	// A nonce this process did not issue must not be accepted, otherwise an
	// attacker could pick their own and precompute responses offline.
	auth, _ := NewAuthenticator("vocat")
	other, _ := NewAuthenticator("vocat")
	message := authorizedRegister(t, auth, testCredentials(), other.Nonce())
	if got := auth.Verify(message, testCredentials(), "1.2.3.4:5060"); got != ResultChallenge {
		t.Fatalf("Verify() = %v, want ResultChallenge for a foreign nonce", got)
	}
}

func TestVerifyRejectsTamperedNonce(t *testing.T) {
	auth, _ := NewAuthenticator("vocat")
	nonce := auth.Nonce()
	// Flip the signature: the timestamp is readable but must not be forgeable.
	issued, _, _ := strings.Cut(nonce, ":")
	tampered := issued + ":deadbeefdeadbeefdeadbeefdeadbeef"
	message := authorizedRegister(t, auth, testCredentials(), tampered)
	if got := auth.Verify(message, testCredentials(), "1.2.3.4:5060"); got != ResultChallenge {
		t.Fatalf("Verify() = %v, want ResultChallenge for a tampered nonce", got)
	}
}

func TestStaleNonceReChallengesWithoutCountingAFailure(t *testing.T) {
	// A client that sat idle past the nonce lifetime must be re-challenged, not
	// locked out — otherwise a phone left on overnight would trip the limiter.
	auth, _ := NewAuthenticator("vocat")
	stale := staleNonce(auth)
	source := "1.2.3.4:5060"
	for attempt := 0; attempt < maxFailures+4; attempt++ {
		message := authorizedRegister(t, auth, testCredentials(), stale)
		if got := auth.Verify(message, testCredentials(), source); got != ResultChallenge {
			t.Fatalf("attempt %d: Verify() = %v, want ResultChallenge", attempt, got)
		}
	}
	if auth.LockedSources() != 0 {
		t.Fatal("a stale nonce must not count as a password failure")
	}
	// A fresh challenge from the same client must still work.
	fresh := authorizedRegister(t, auth, testCredentials(), auth.Nonce())
	if got := auth.Verify(fresh, testCredentials(), source); got != ResultOK {
		t.Fatalf("Verify() after re-challenge = %v, want ResultOK", got)
	}
}

func TestLockoutAfterRepeatedWrongPasswords(t *testing.T) {
	// A LAN-reachable SIP port attracts scanners; each guess must not be free.
	auth, _ := NewAuthenticator("vocat")
	source := "9.9.9.9:5060"
	bad := Credentials{Username: "alice", Password: "wrong", Realm: "vocat"}
	locked := false
	for attempt := 0; attempt < maxFailures+2; attempt++ {
		message := authorizedRegister(t, auth, bad, auth.Nonce())
		result := auth.Verify(message, testCredentials(), source)
		if result == ResultLocked {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatalf("no lockout after %d wrong passwords", maxFailures+2)
	}
	if auth.LockedSources() != 1 {
		t.Fatalf("LockedSources() = %d, want 1", auth.LockedSources())
	}
	// Even a correct password is refused while locked, so a scanner that guesses
	// right on attempt N+1 still gets nothing.
	good := authorizedRegister(t, auth, testCredentials(), auth.Nonce())
	if got := auth.Verify(good, testCredentials(), source); got != ResultLocked {
		t.Fatalf("Verify() while locked = %v, want ResultLocked", got)
	}
	// A different source is unaffected.
	other := authorizedRegister(t, auth, testCredentials(), auth.Nonce())
	if got := auth.Verify(other, testCredentials(), "10.0.0.1:5060"); got != ResultOK {
		t.Fatalf("another source was affected by the lockout: %v", got)
	}
}

func TestSuccessClearsFailureCount(t *testing.T) {
	auth, _ := NewAuthenticator("vocat")
	source := "7.7.7.7:5060"
	bad := Credentials{Username: "alice", Password: "wrong", Realm: "vocat"}
	for attempt := 0; attempt < maxFailures-1; attempt++ {
		message := authorizedRegister(t, auth, bad, auth.Nonce())
		if got := auth.Verify(message, testCredentials(), source); got != ResultReject {
			t.Fatalf("attempt %d: Verify() = %v", attempt, got)
		}
	}
	good := authorizedRegister(t, auth, testCredentials(), auth.Nonce())
	if got := auth.Verify(good, testCredentials(), source); got != ResultOK {
		t.Fatalf("Verify() = %v, want ResultOK", got)
	}
	// The counter reset, so the next wrong password is not the one that locks.
	message := authorizedRegister(t, auth, bad, auth.Nonce())
	if got := auth.Verify(message, testCredentials(), source); got != ResultReject {
		t.Fatalf("Verify() = %v, want ResultReject (counter should have reset)", got)
	}
	if auth.LockedSources() != 0 {
		t.Fatal("a success must clear the failure count")
	}
}

func TestProxyAuthorizationHeaderIsAccepted(t *testing.T) {
	// Some clients answer with Proxy-Authorization even for a REGISTER.
	auth, _ := NewAuthenticator("vocat")
	credentials := testCredentials()
	uri := "sip:vocat.local"
	challenge := Challenge{
		Realm: auth.Realm(), Nonce: auth.Nonce(), Username: credentials.Username,
		URI: uri, QOP: "auth", CNonce: "c", NonceCount: "00000001",
	}
	challenge.Response = DigestResponse(credentials, "REGISTER", uri, challenge)
	message, err := Parse([]byte("REGISTER " + uri + " SIP/2.0\r\nCSeq: 1 REGISTER\r\n" +
		`Proxy-Authorization: Digest username="alice", realm="` + challenge.Realm +
		`", nonce="` + challenge.Nonce + `", uri="` + uri + `", response="` + challenge.Response +
		`", qop=auth, nc=00000001, cnonce="c"` + "\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := auth.Verify(message, credentials, "1.2.3.4:5060"); got != ResultOK {
		t.Fatalf("Verify() = %v, want ResultOK", got)
	}
}

func TestDigestWithoutQOPIsSupported(t *testing.T) {
	// RFC 2069 style, still emitted by some older clients.
	auth, _ := NewAuthenticator("vocat")
	credentials := testCredentials()
	uri := "sip:vocat.local"
	challenge := Challenge{Realm: auth.Realm(), Nonce: auth.Nonce(), Username: "alice", URI: uri}
	challenge.Response = DigestResponse(credentials, "REGISTER", uri, challenge)
	message, _ := Parse([]byte("REGISTER " + uri + " SIP/2.0\r\nCSeq: 1 REGISTER\r\n" +
		`Authorization: Digest username="alice", realm="` + challenge.Realm +
		`", nonce="` + challenge.Nonce + `", uri="` + uri +
		`", response="` + challenge.Response + `"` + "\r\n\r\n"))
	if got := auth.Verify(message, credentials, "1.2.3.4:5060"); got != ResultOK {
		t.Fatalf("Verify() = %v, want ResultOK for qop-less digest", got)
	}
}

func TestParseAuthorizationSplitsQuotedCommas(t *testing.T) {
	// A quoted value may contain a comma; splitting naively would corrupt the
	// nonce and turn every registration into a mysterious failure.
	challenge, err := ParseAuthorization(
		`Digest username="alice", realm="vocat, inc", nonce="a,b,c", response="deadbeef"`)
	if err != nil {
		t.Fatalf("ParseAuthorization() error = %v", err)
	}
	if challenge.Realm != "vocat, inc" {
		t.Fatalf("Realm = %q", challenge.Realm)
	}
	if challenge.Nonce != "a,b,c" {
		t.Fatalf("Nonce = %q", challenge.Nonce)
	}
}

func TestParseAuthorizationRejectsBadInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":        "",
		"wrong scheme": `Basic dXNlcjpwYXNz`,
		"no response":  `Digest username="a", nonce="n"`,
		"no nonce":     `Digest username="a", response="r"`,
		"no username":  `Digest nonce="n", response="r"`,
	} {
		if _, err := ParseAuthorization(input); err == nil {
			t.Fatalf("%s: ParseAuthorization(%q) must fail", name, input)
		}
	}
}

func TestChallengeHeaderIsWellFormed(t *testing.T) {
	auth, _ := NewAuthenticator("")
	if auth.Realm() != "vocat" {
		t.Fatalf("Realm() = %q, want the default", auth.Realm())
	}
	header := auth.ChallengeHeader()
	for _, want := range []string{"Digest ", `realm="vocat"`, "nonce=", "algorithm=MD5", `qop="auth"`} {
		if !strings.Contains(header, want) {
			t.Fatalf("ChallengeHeader() = %q, missing %q", header, want)
		}
	}
	// A parser must be able to read back what we emit.
	if _, err := ParseAuthorization(header + `, username="a", response="r"`); err != nil {
		t.Fatalf("our own challenge does not round-trip: %v", err)
	}
}

func TestNoncesAreUnpredictableAcrossProcesses(t *testing.T) {
	first, _ := NewAuthenticator("vocat")
	second, _ := NewAuthenticator("vocat")
	// Same timestamp, different secret: the signatures must differ, or a restart
	// would let an old capture be replayed.
	if first.Nonce() == second.Nonce() {
		t.Fatal("two authenticators produced the same nonce")
	}
}

// staleNonce forges a correctly signed nonce with an expired timestamp, using
// the authenticator's own signing path so only its age is wrong.
func staleNonce(auth *Authenticator) string {
	return auth.signNonce(time.Now().Add(-2 * nonceLifetime).Unix())
}
