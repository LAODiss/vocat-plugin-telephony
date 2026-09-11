package sip

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseRegisterWithCompactHeaders(t *testing.T) {
	// Clients mix compact and long forms freely; a parser that missed "f:" would
	// silently drop the From header and reject a valid registration.
	raw := "REGISTER sip:vocat.local SIP/2.0\r\n" +
		"v: SIP/2.0/UDP 192.168.1.50:5060;branch=z9hG4bK1\r\n" +
		"f: <sip:alice@vocat.local>;tag=abc\r\n" +
		"t: <sip:alice@vocat.local>\r\n" +
		"i: call-1@192.168.1.50\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"m: <sip:alice@192.168.1.50:5060>;expires=600\r\n" +
		"Expires: 3600\r\n" +
		"l: 0\r\n\r\n"

	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if message.IsResponse || message.Method != "REGISTER" {
		t.Fatalf("parsed as %+v", message)
	}
	if got := message.Get("From"); got != "<sip:alice@vocat.local>;tag=abc" {
		t.Fatalf("From = %q (compact form not expanded)", got)
	}
	if got := message.Get("Via"); !strings.Contains(got, "branch=z9hG4bK1") {
		t.Fatalf("Via = %q", got)
	}
	if got := message.CallID(); got != "call-1@192.168.1.50" {
		t.Fatalf("CallID = %q", got)
	}
	number, method := message.CSeq()
	if number != 1 || method != "REGISTER" {
		t.Fatalf("CSeq = %d %q", number, method)
	}
	if got := Tag(message.Get("From")); got != "abc" {
		t.Fatalf("From tag = %q", got)
	}
}

func TestExpiresPrefersHeaderThenContactParam(t *testing.T) {
	withHeader, err := Parse([]byte("REGISTER sip:v SIP/2.0\r\nExpires: 1800\r\n" +
		"Contact: <sip:a@1.2.3.4>;expires=600\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	value, ok := Expires(withHeader)
	if !ok || value != 1800 {
		t.Fatalf("Expires() = %d, %v; want 1800 from the header", value, ok)
	}

	contactOnly, err := Parse([]byte("REGISTER sip:v SIP/2.0\r\n" +
		"Contact: <sip:a@1.2.3.4>;expires=600\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	value, ok = Expires(contactOnly)
	if !ok || value != 600 {
		t.Fatalf("Expires() = %d, %v; want 600 from the Contact param", value, ok)
	}

	neither, err := Parse([]byte("REGISTER sip:v SIP/2.0\r\nContact: <sip:a@1.2.3.4>\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, ok := Expires(neither); ok {
		t.Fatal("Expires() must report absence so the caller can apply its default")
	}
}

func TestIsUnregister(t *testing.T) {
	zero, _ := Parse([]byte("REGISTER sip:v SIP/2.0\r\nExpires: 0\r\n" +
		"Contact: <sip:a@1.2.3.4>\r\n\r\n"))
	if !IsUnregister(zero) {
		t.Fatal("Expires: 0 must read as an unregister")
	}
	wildcard, _ := Parse([]byte("REGISTER sip:v SIP/2.0\r\nContact: *\r\n\r\n"))
	if !IsUnregister(wildcard) {
		t.Fatal("a wildcard Contact must read as an unregister")
	}
	normal, _ := Parse([]byte("REGISTER sip:v SIP/2.0\r\nExpires: 3600\r\n" +
		"Contact: <sip:a@1.2.3.4>\r\n\r\n"))
	if IsUnregister(normal) {
		t.Fatal("a normal registration must not read as an unregister")
	}
}

func TestParseResponse(t *testing.T) {
	message, err := Parse([]byte("SIP/2.0 401 Unauthorized\r\n" +
		"WWW-Authenticate: Digest realm=\"vocat\", nonce=\"n1\"\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !message.IsResponse || message.StatusCode != 401 || message.Reason != "Unauthorized" {
		t.Fatalf("parsed as %+v", message)
	}
}

func TestParseUnfoldsContinuationLines(t *testing.T) {
	message, err := Parse([]byte("INVITE sip:1234@v SIP/2.0\r\n" +
		"Subject: a very\r\n  long subject\r\n\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := message.Get("Subject"); got != "a very long subject" {
		t.Fatalf("Subject = %q, want the folded lines joined", got)
	}
}

func TestParseUsesContentLengthForBody(t *testing.T) {
	// A UDP datagram can carry trailing padding; Content-Length is authoritative
	// so the padding must not leak into the SDP body.
	body := "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"
	raw := "INVITE sip:1234@v SIP/2.0\r\nContent-Type: application/sdp\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body + "GARBAGE"
	message, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if string(message.Body) != body {
		t.Fatalf("Body = %q, want the Content-Length prefix only", message.Body)
	}
}

func TestParseRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("Parse(nil) must fail")
	}
	oversized := make([]byte, MaxMessageBytes+1)
	for index := range oversized {
		oversized[index] = 'A'
	}
	if _, err := Parse(oversized); err == nil {
		t.Fatal("an oversized datagram must be refused, not truncated")
	}
	if _, err := Parse([]byte("garbage\r\n\r\n")); err == nil {
		t.Fatal("a malformed start line must fail")
	}
	if _, err := Parse([]byte("SIP/2.0 999 Nope\r\n\r\n")); err == nil {
		t.Fatal("an out-of-range status code must fail")
	}
}

func TestEncodeRewritesContentLength(t *testing.T) {
	// A stale Content-Length is a classic cause of a hung dialog, so Encode must
	// always recompute it.
	message := &Message{Method: "INVITE", URI: "sip:1234@v"}
	message.Add("Content-Length", "999")
	message.Body = []byte("v=0\r\n")
	encoded := string(message.Encode())
	if strings.Contains(encoded, "999") {
		t.Fatalf("stale Content-Length survived: %q", encoded)
	}
	if !strings.Contains(encoded, "Content-Length: 5\r\n") {
		t.Fatalf("Content-Length not recomputed: %q", encoded)
	}
	if !strings.HasPrefix(encoded, "INVITE sip:1234@v SIP/2.0\r\n") {
		t.Fatalf("request line wrong: %q", encoded)
	}
}

func TestEncodeResponseFillsReasonPhrase(t *testing.T) {
	message := &Message{IsResponse: true, StatusCode: 486}
	if got := string(message.Encode()); !strings.HasPrefix(got, "SIP/2.0 486 Busy Here\r\n") {
		t.Fatalf("encoded = %q", got)
	}
}

func TestSetAndRemoveHeaders(t *testing.T) {
	message := &Message{Method: "INVITE", URI: "sip:v"}
	message.Add("Via", "one")
	message.Add("Via", "two")
	if len(message.All("Via")) != 2 {
		t.Fatal("All() must return every occurrence, order matters for routing")
	}
	message.Set("Via", "only")
	if values := message.All("Via"); len(values) != 1 || values[0] != "only" {
		t.Fatalf("Set() did not collapse duplicates: %v", values)
	}
	message.Set("Max-Forwards", "70")
	if message.Get("Max-Forwards") != "70" {
		t.Fatal("Set() must append an absent header")
	}
	message.Remove("Via")
	if message.Get("Via") != "" {
		t.Fatal("Remove() left a header behind")
	}
}

func TestParseURIForms(t *testing.T) {
	for name, testCase := range map[string]struct {
		input string
		want  URI
	}{
		"bare":            {"sip:alice@example.com", URI{Scheme: "sip", User: "alice", Host: "example.com"}},
		"with port":       {"sip:alice@example.com:5080", URI{Scheme: "sip", User: "alice", Host: "example.com", Port: 5080}},
		"angle brackets":  {"<sip:bob@1.2.3.4:5060>", URI{Scheme: "sip", User: "bob", Host: "1.2.3.4", Port: 5060}},
		"display name":    {`"Alice B" <sip:alice@example.com>`, URI{Scheme: "sip", User: "alice", Host: "example.com"}},
		"transport param": {"<sip:a@1.2.3.4;transport=tcp>", URI{Scheme: "sip", User: "a", Host: "1.2.3.4", Transport: "tcp"}},
		"no user":         {"sip:example.com", URI{Scheme: "sip", Host: "example.com"}},
		"sips":            {"sips:a@example.com", URI{Scheme: "sips", User: "a", Host: "example.com"}},
		"tel":             {"tel:+447700900123", URI{Scheme: "tel", Host: "+447700900123"}},
		"ipv6":            {"sip:a@[2001:db8::1]:5060", URI{Scheme: "sip", User: "a", Host: "2001:db8::1", Port: 5060}},
	} {
		got, err := ParseURI(testCase.input)
		if err != nil {
			t.Fatalf("%s: ParseURI(%q) error = %v", name, testCase.input, err)
		}
		if got != testCase.want {
			t.Fatalf("%s: ParseURI(%q) = %+v, want %+v", name, testCase.input, got, testCase.want)
		}
	}
}

func TestParseURIStripsPassword(t *testing.T) {
	// A gateway must never propagate a password it happens to receive.
	uri, err := ParseURI("sip:alice:secret@example.com")
	if err != nil {
		t.Fatalf("ParseURI() error = %v", err)
	}
	if uri.User != "alice" {
		t.Fatalf("User = %q, want the password stripped", uri.User)
	}
	if strings.Contains(uri.String(), "secret") {
		t.Fatalf("String() leaked the password: %q", uri.String())
	}
}

func TestParseURIRejectsBadInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":           "",
		"bad scheme":      "http://example.com",
		"unterminated":    "<sip:a@example.com",
		"bad port":        "sip:a@example.com:99999",
		"no host":         "sip:alice@",
		"unterminated v6": "sip:a@[2001:db8::1",
	} {
		if _, err := ParseURI(input); err == nil {
			t.Fatalf("%s: ParseURI(%q) must fail", name, input)
		}
	}
}

func TestURIString(t *testing.T) {
	uri := URI{Scheme: "sip", User: "alice", Host: "1.2.3.4", Port: 5060, Transport: "udp"}
	if got := uri.String(); got != "sip:alice@1.2.3.4:5060;transport=udp" {
		t.Fatalf("String() = %q", got)
	}
	noPort := URI{User: "a", Host: "example.com"}
	if got := noPort.String(); got != "sip:a@example.com" {
		t.Fatalf("String() = %q, want the default scheme and no port", got)
	}
}

func TestParamHandlesQuotedAndTerminatedValues(t *testing.T) {
	if got := Param("<sip:a@b>;tag=xyz;other=1", "tag"); got != "xyz" {
		t.Fatalf("Param(tag) = %q", got)
	}
	if got := Param(`Digest realm="vocat";nonce="abc"`, "nonce"); got != "abc" {
		t.Fatalf("Param(nonce) = %q", got)
	}
	if got := Param("<sip:a@b>", "tag"); got != "" {
		t.Fatalf("Param on an absent parameter = %q, want empty", got)
	}
}

func TestReasonPhraseFallsBackByClass(t *testing.T) {
	if ReasonPhrase(200) != "OK" || ReasonPhrase(486) != "Busy Here" {
		t.Fatal("known codes must map to their standard phrase")
	}
	// An unknown code must still produce something, or the response line would
	// be malformed.
	if ReasonPhrase(499) == "" || ReasonPhrase(599) == "" {
		t.Fatal("unknown codes must fall back to a class phrase")
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
