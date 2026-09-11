package sipgw

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"vocat-plugin-telephony/internal/rtp"
	"vocat-plugin-telephony/internal/sip"
	"vocat-plugin-telephony/internal/vocat"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startGateway brings up a gateway on a loopback ephemeral port with a fake
// vocat behind it.
func startGateway(t *testing.T, adjust func(*Config)) (*Gateway, *fakeVocat) {
	t.Helper()
	fake := newFakeVocat()
	t.Cleanup(fake.Close)

	client, err := fake.client()
	if err != nil {
		t.Fatalf("vocat.New() error = %v", err)
	}
	config := Config{
		ListenAddress: "127.0.0.1:0",
		AdvertiseIP:   "127.0.0.1",
		Realm:         "vocat",
		Account:       Account{Username: "alice", Password: "s3cret", DeviceID: "ec20"},
	}
	if adjust != nil {
		adjust(&config)
	}
	gateway, err := New(config, client, quietLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := gateway.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(gateway.Stop)
	return gateway, fake
}

// exchange sends a request and returns the first response, retrying reads until
// the deadline because the gateway may send a provisional response first.
func exchange(t *testing.T, phone *softphone, raw string, want func(*sip.Message) bool) *sip.Message {
	t.Helper()
	if err := phone.send(raw); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	return await(t, phone, 3*time.Second, want)
}

// await reads until a message satisfies the predicate.
func await(t *testing.T, phone *softphone, timeout time.Duration, want func(*sip.Message) bool) *sip.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 8192)
	for time.Now().Before(deadline) {
		_ = phone.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		count, _, err := phone.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		message, parseErr := sip.Parse(buffer[:count])
		if parseErr != nil {
			continue
		}
		if want == nil || want(message) {
			return message
		}
	}
	t.Fatalf("no matching SIP message within %s", timeout)
	return nil
}

func isResponse(status int) func(*sip.Message) bool {
	return func(message *sip.Message) bool {
		return message.IsResponse && message.StatusCode == status
	}
}

func isRequest(method string) func(*sip.Message) bool {
	return func(message *sip.Message) bool {
		return !message.IsResponse && message.Method == method
	}
}

// registerPhone completes the challenge/response registration handshake and
// returns the phone, already registered.
func registerPhone(t *testing.T, gateway *Gateway) *softphone {
	t.Helper()
	phone, err := newSoftphone(gateway.Status().Address)
	if err != nil {
		t.Fatalf("newSoftphone() error = %v", err)
	}
	t.Cleanup(phone.Close)

	challenge := exchange(t, phone, registerRaw(phone, 1, "", ""), isResponse(401))
	authHeader := answerChallenge(t, challenge, "REGISTER", "sip:vocat")
	granted := exchange(t, phone, registerRaw(phone, 2, authHeader, ""), isResponse(200))
	if granted.Get("Expires") == "" {
		t.Fatalf("200 OK carried no Expires: %q", granted.Encode())
	}
	return phone
}

func registerRaw(phone *softphone, cseq int, authHeader, expires string) string {
	if expires == "" {
		expires = "600"
	}
	raw := "REGISTER sip:vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKreg" + itoa(cseq) + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:alice@vocat>;tag=regtag\r\n" +
		"To: <sip:alice@vocat>\r\n" +
		"Call-ID: reg-call-id\r\n" +
		"CSeq: " + itoa(cseq) + " REGISTER\r\n" +
		"Contact: <sip:alice@" + phone.address() + ">\r\n" +
		"Expires: " + expires + "\r\n" +
		"User-Agent: TestPhone/1.0\r\n"
	if authHeader != "" {
		raw += "Authorization: " + authHeader + "\r\n"
	}
	return raw + "\r\n"
}

// answerChallenge computes a correct digest response for a 401.
func answerChallenge(t *testing.T, response *sip.Message, method, uri string) string {
	t.Helper()
	header := response.Get("WWW-Authenticate")
	if header == "" {
		t.Fatalf("401 carried no WWW-Authenticate: %q", response.Encode())
	}
	challenge, err := sip.ParseAuthorization(header + `, username="alice", response="0"`)
	if err != nil {
		t.Fatalf("could not read our own challenge: %v", err)
	}
	credentials := sip.Credentials{Username: "alice", Password: "s3cret", Realm: challenge.Realm}
	answer := sip.Challenge{
		Realm: challenge.Realm, Nonce: challenge.Nonce, Username: "alice",
		URI: uri, QOP: "auth", CNonce: "cnonce", NonceCount: "00000001",
	}
	answer.Response = sip.DigestResponse(credentials, method, uri, answer)
	return fmt.Sprintf(`Digest username="alice", realm="%s", nonce="%s", uri="%s", `+
		`response="%s", qop=auth, nc=00000001, cnonce="cnonce"`,
		answer.Realm, answer.Nonce, uri, answer.Response)
}

const phoneOfferTemplate = "v=0\r\n" +
	"o=alice 1 1 IN IP4 127.0.0.1\r\n" +
	"s=Talk\r\n" +
	"c=IN IP4 127.0.0.1\r\n" +
	"t=0 0\r\n" +
	"m=audio %d RTP/AVP 8 0 101\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=ptime:20\r\n"

func inviteRaw(phone *softphone, number, authHeader string, rtpPort int) string {
	body := fmt.Sprintf(phoneOfferTemplate, rtpPort)
	raw := "INVITE sip:" + number + "@vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKinv1\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:alice@vocat>;tag=invtag\r\n" +
		"To: <sip:" + number + "@vocat>\r\n" +
		"Call-ID: out-call-id\r\n" +
		"CSeq: 20 INVITE\r\n" +
		"Contact: <sip:alice@" + phone.address() + ">\r\n" +
		"Content-Type: application/sdp\r\n"
	if authHeader != "" {
		raw += "Authorization: " + authHeader + "\r\n"
	}
	raw += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
	return raw
}

func TestRegistrationRequiresDigestAuth(t *testing.T) {
	gateway, _ := startGateway(t, nil)
	phone, err := newSoftphone(gateway.Status().Address)
	if err != nil {
		t.Fatalf("newSoftphone() error = %v", err)
	}
	defer phone.Close()

	// An unauthenticated REGISTER must be challenged, never accepted: this port
	// is the only thing between a LAN and the operator's SIM.
	challenge := exchange(t, phone, registerRaw(phone, 1, "", ""), isResponse(401))
	if !strings.Contains(challenge.Get("WWW-Authenticate"), "nonce=") {
		t.Fatalf("challenge missing a nonce: %q", challenge.Get("WWW-Authenticate"))
	}
	if gateway.Status().Registered {
		t.Fatal("an unauthenticated REGISTER created a binding")
	}

	authHeader := answerChallenge(t, challenge, "REGISTER", "sip:vocat")
	granted := exchange(t, phone, registerRaw(phone, 2, authHeader, ""), isResponse(200))
	if !strings.Contains(granted.Get("Contact"), "expires=") {
		t.Fatalf("200 OK Contact missing expires: %q", granted.Get("Contact"))
	}

	status := gateway.Status()
	if !status.Registered || len(status.Bindings) != 1 {
		t.Fatalf("Status() = %+v, want one binding", status)
	}
	// The delivery target must be the observed source, not the Contact host: a
	// phone behind NAT advertises an unreachable address.
	if status.Bindings[0].Target != phone.address() {
		t.Fatalf("binding target = %q, want the observed source %q",
			status.Bindings[0].Target, phone.address())
	}
	if status.Bindings[0].UserAgent != "TestPhone/1.0" {
		t.Fatalf("UserAgent = %q", status.Bindings[0].UserAgent)
	}
}

func TestWrongPasswordIsRechallengedNotAccepted(t *testing.T) {
	gateway, _ := startGateway(t, nil)
	phone, err := newSoftphone(gateway.Status().Address)
	if err != nil {
		t.Fatalf("newSoftphone() error = %v", err)
	}
	defer phone.Close()

	challenge := exchange(t, phone, registerRaw(phone, 1, "", ""), isResponse(401))
	header := challenge.Get("WWW-Authenticate")
	parsed, err := sip.ParseAuthorization(header + `, username="alice", response="0"`)
	if err != nil {
		t.Fatalf("ParseAuthorization() error = %v", err)
	}
	bad := sip.Challenge{
		Realm: parsed.Realm, Nonce: parsed.Nonce, Username: "alice",
		URI: "sip:vocat", QOP: "auth", CNonce: "c", NonceCount: "00000001",
	}
	bad.Response = sip.DigestResponse(
		sip.Credentials{Username: "alice", Password: "wrong", Realm: parsed.Realm},
		"REGISTER", "sip:vocat", bad)
	authHeader := fmt.Sprintf(`Digest username="alice", realm="%s", nonce="%s", uri="sip:vocat", `+
		`response="%s", qop=auth, nc=00000001, cnonce="c"`, bad.Realm, bad.Nonce, bad.Response)

	// A wrong password gets a fresh challenge rather than 403, so a user who
	// mistyped can retry without reconfiguring the client.
	exchange(t, phone, registerRaw(phone, 2, authHeader, ""), isResponse(401))
	if gateway.Status().Registered {
		t.Fatal("a wrong password created a binding")
	}
}

func TestUnregisterDropsTheBinding(t *testing.T) {
	gateway, _ := startGateway(t, nil)
	phone := registerPhone(t, gateway)

	challenge := exchange(t, phone, registerRaw(phone, 3, "", "0"), isResponse(401))
	authHeader := answerChallenge(t, challenge, "REGISTER", "sip:vocat")
	response := exchange(t, phone, registerRaw(phone, 4, authHeader, "0"), isResponse(200))
	if response.Get("Expires") != "0" {
		t.Fatalf("unregister response Expires = %q, want 0", response.Get("Expires"))
	}
	if gateway.Status().Registered {
		t.Fatal("the binding survived an unregister")
	}
}

func TestSourceAllowlistDropsForeignPackets(t *testing.T) {
	// A restricted gateway drops silently rather than answering 403: replying
	// tells a scanner the port is live.
	gateway, _ := startGateway(t, func(config *Config) {
		config.AllowedSources = []string{"10.99.0.0/24"}
	})
	phone, err := newSoftphone(gateway.Status().Address)
	if err != nil {
		t.Fatalf("newSoftphone() error = %v", err)
	}
	defer phone.Close()

	if err := phone.send(registerRaw(phone, 1, "", "")); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	_ = phone.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 2048)
	if _, _, err := phone.conn.ReadFromUDP(buffer); err == nil {
		t.Fatal("a disallowed source received a reply")
	}
	if !gateway.Status().Restricted {
		t.Fatal("Status() should report the gateway is restricted")
	}
}

func TestOptionsKeepaliveIsAnswered(t *testing.T) {
	// Clients use OPTIONS as a keepalive; not answering makes them tear down
	// their registration.
	gateway, _ := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	raw := "OPTIONS sip:vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKopt\r\n" +
		"From: <sip:alice@vocat>;tag=opt\r\n" +
		"To: <sip:vocat>\r\n" +
		"Call-ID: opt-1\r\n" +
		"CSeq: 1 OPTIONS\r\n\r\n"
	exchange(t, phone, raw, isResponse(200))
}

func TestUnsupportedMethodIsRejectedWithAllow(t *testing.T) {
	gateway, _ := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	raw := "SUBSCRIBE sip:vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKsub\r\n" +
		"From: <sip:alice@vocat>;tag=sub\r\n" +
		"To: <sip:vocat>\r\n" +
		"Call-ID: sub-1\r\n" +
		"CSeq: 1 SUBSCRIBE\r\n\r\n"
	response := exchange(t, phone, raw, isResponse(405))
	if !strings.Contains(response.Get("Allow"), "INVITE") {
		t.Fatalf("405 must advertise what is allowed, got %q", response.Get("Allow"))
	}
}

func TestOutboundCallDialsVocatAndRingsOnlyAfterAcceptance(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)

	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	challenge := exchange(t, phone, inviteRaw(phone, "10086", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")

	if err := phone.send(inviteRaw(phone, "10086", authHeader, media.LocalPort())); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	// 180 must arrive only after vocat accepted the dial: ringback for a call
	// that was never placed is the most confusing failure a user can hit.
	ringing := await(t, phone, 5*time.Second, isResponse(180))
	if sip.Tag(ringing.Get("To")) == "" {
		t.Fatal("180 must carry a To tag to establish the dialog")
	}
	dialed, _, _ := fake.snapshot()
	if len(dialed) != 1 || dialed[0] != "10086" {
		t.Fatalf("vocat dialled %v, want [10086]", dialed)
	}

	// vocat reports the far end picked up; the gateway must answer with SDP.
	fake.setState("vocat-out-1", "active", true)
	answer := await(t, phone, 5*time.Second, isResponse(200))
	if !strings.Contains(strings.ToLower(answer.Get("Content-Type")), "sdp") {
		t.Fatalf("200 OK carried no SDP: %q", answer.Encode())
	}
	answerMedia, err := parseSDP(answer.Body)
	if err != nil {
		t.Fatalf("gateway answer SDP is unusable: %v", err)
	}
	if answerMedia.Payload != rtp.PayloadPCMA {
		t.Fatalf("negotiated %s, want PCMA (the phone's first supported codec)",
			answerMedia.Payload.Name())
	}
	// The answer must not offer DTMF the gateway cannot send.
	if strings.Contains(strings.ToLower(string(answer.Body)), "telephone-event") {
		t.Fatalf("answer announced DTMF:\n%s", answer.Body)
	}
	if gateway.Status().ActiveCalls != 1 {
		t.Fatalf("ActiveCalls = %d, want 1", gateway.Status().ActiveCalls)
	}
}

func TestOutboundCallRejectsUnusableSDPWith488(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)

	body := "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 40000 RTP/AVP 96\r\n" +
		"a=rtpmap:96 opus/48000/2\r\n"
	raw := "INVITE sip:10086@vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKopus\r\n" +
		"From: <sip:alice@vocat>;tag=opus\r\n" +
		"To: <sip:10086@vocat>\r\n" +
		"Call-ID: opus-call\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:alice@" + phone.address() + ">\r\n" +
		"Content-Type: application/sdp\r\n"
	challenge := exchange(t, phone, raw+fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))+body,
		isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")

	exchange(t, phone,
		raw+"Authorization: "+authHeader+"\r\n"+fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))+body,
		isResponse(488))

	// vocat must never have been dialled for a call that cannot carry audio.
	dialed, _, _ := fake.snapshot()
	if len(dialed) != 0 {
		t.Fatalf("vocat was dialled for an unusable offer: %v", dialed)
	}
}

func TestOutboundCallRejectsBadNumberWith484(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	// A single digit is below vocat's minimum, so the gateway refuses locally
	// rather than round-tripping a rejection.
	challenge := exchange(t, phone, inviteRaw(phone, "1", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:1@vocat")
	exchange(t, phone, inviteRaw(phone, "1", authHeader, media.LocalPort()), isResponse(484))

	if dialed, _, _ := fake.snapshot(); len(dialed) != 0 {
		t.Fatalf("vocat was dialled with an invalid number: %v", dialed)
	}
}

func TestOutboundCallReportsVocatRefusalAs503(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	fake.setDialErr(true)
	phone := registerPhone(t, gateway)
	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	challenge := exchange(t, phone, inviteRaw(phone, "10086", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")
	if err := phone.send(inviteRaw(phone, "10086", authHeader, media.LocalPort())); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	// 503, not 500: the request was fine, the downstream service could not carry
	// it, and a phone presents that as "unavailable".
	await(t, phone, 5*time.Second, isResponse(503))
	if gateway.Status().ActiveCalls != 0 {
		t.Fatal("a failed dial left a dialog behind")
	}
}

func TestPhoneHangupHangsUpVocat(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	challenge := exchange(t, phone, inviteRaw(phone, "10086", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")
	if err := phone.send(inviteRaw(phone, "10086", authHeader, media.LocalPort())); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	await(t, phone, 5*time.Second, isResponse(180))

	bye := "BYE sip:vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKbye\r\n" +
		"From: <sip:alice@vocat>;tag=invtag\r\n" +
		"To: <sip:10086@vocat>\r\n" +
		"Call-ID: out-call-id\r\n" +
		"CSeq: 21 BYE\r\n\r\n"
	exchange(t, phone, bye, isResponse(200))

	// Leaving the vocat call running would keep the SIM occupied and keep
	// billing after the phone is gone.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, hungUp := fake.snapshot(); len(hungUp) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, hungUp := fake.snapshot()
	if len(hungUp) == 0 {
		t.Fatal("the phone's BYE did not hang up the vocat call")
	}
	if gateway.Status().ActiveCalls != 0 {
		t.Fatalf("ActiveCalls = %d after BYE, want 0", gateway.Status().ActiveCalls)
	}
}

func TestByeForUnknownDialogGets481(t *testing.T) {
	// Answering 200 would leave the client believing a call it does not have was
	// just ended.
	gateway, _ := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	bye := "BYE sip:vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKghost\r\n" +
		"From: <sip:alice@vocat>;tag=ghost\r\n" +
		"To: <sip:10086@vocat>\r\n" +
		"Call-ID: no-such-call\r\n" +
		"CSeq: 9 BYE\r\n\r\n"
	exchange(t, phone, bye, isResponse(481))
}

func TestPhoneCancelDuringRingingTerminatesBothSides(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	challenge := exchange(t, phone, inviteRaw(phone, "10086", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")
	if err := phone.send(inviteRaw(phone, "10086", authHeader, media.LocalPort())); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	await(t, phone, 5*time.Second, isResponse(180))

	cancel := "CANCEL sip:10086@vocat SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + phone.address() + ";branch=z9hG4bKinv1\r\n" +
		"From: <sip:alice@vocat>;tag=invtag\r\n" +
		"To: <sip:10086@vocat>\r\n" +
		"Call-ID: out-call-id\r\n" +
		"CSeq: 20 CANCEL\r\n\r\n"
	if err := phone.send(cancel); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	// A CANCEL is answered 200, then the pending INVITE is answered 487.
	await(t, phone, 3*time.Second, isResponse(200))
	await(t, phone, 3*time.Second, isResponse(487))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, hungUp := fake.snapshot(); len(hungUp) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, _, hungUp := fake.snapshot(); len(hungUp) == 0 {
		t.Fatal("CANCEL did not hang up the vocat call")
	}
}

func TestVocatCallDisappearingEndsTheDialog(t *testing.T) {
	// vocat drops a finished call from its list shortly after it ends, so absence
	// is the normal end-of-call signal rather than an error.
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	media, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer media.Close()

	challenge := exchange(t, phone, inviteRaw(phone, "10086", "", media.LocalPort()), isResponse(401))
	authHeader := answerChallenge(t, challenge, "INVITE", "sip:10086@vocat")
	if err := phone.send(inviteRaw(phone, "10086", authHeader, media.LocalPort())); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	await(t, phone, 5*time.Second, isResponse(180))

	fake.removeCall("vocat-out-1")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if gateway.Status().ActiveCalls == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the dialog outlived its vocat call")
}

func TestInboundCallRingsTheRegisteredPhone(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)

	// vocat reports an inbound call ringing.
	fake.addCall(vocat.Call{
		ID: "vocat-in-1", Number: "+447700900123", Direction: "incoming",
		State: "ringing", StartedAt: time.Now().UTC(),
	})

	invite := await(t, phone, 6*time.Second, isRequest("INVITE"))
	if !strings.Contains(invite.Get("From"), "447700900123") {
		t.Fatalf("INVITE From does not carry the caller: %q", invite.Get("From"))
	}
	offer, err := parseSDP(invite.Body)
	if err != nil {
		t.Fatalf("gateway offer SDP is unusable: %v", err)
	}
	if offer.Port == 0 {
		t.Fatal("offer has no RTP port")
	}
	if strings.Contains(strings.ToLower(string(invite.Body)), "telephone-event") {
		t.Fatalf("offer announced DTMF:\n%s", invite.Body)
	}
	if invite.Get("Contact") == "" {
		t.Fatal("INVITE must carry a Contact for in-dialog requests")
	}
}

func TestInboundAnswerIsForwardedToVocat(t *testing.T) {
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	fake.addCall(vocat.Call{
		ID: "vocat-in-1", Number: "+447700900123", Direction: "incoming",
		State: "ringing", StartedAt: time.Now().UTC(),
	})
	invite := await(t, phone, 6*time.Second, isRequest("INVITE"))

	phoneMedia, err := rtp.Listen(rtp.Options{ListenIP: net.IPv4(127, 0, 0, 1), Payload: rtp.PayloadPCMA})
	if err != nil {
		t.Fatalf("rtp.Listen() error = %v", err)
	}
	defer phoneMedia.Close()

	body := fmt.Sprintf("v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n"+
		"t=0 0\r\nm=audio %d RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n", phoneMedia.LocalPort())
	ok := "SIP/2.0 200 OK\r\n" +
		"Via: " + invite.Get("Via") + "\r\n" +
		"From: " + invite.Get("From") + "\r\n" +
		"To: " + invite.Get("To") + ";tag=phonetag\r\n" +
		"Call-ID: " + invite.CallID() + "\r\n" +
		"CSeq: " + invite.Get("CSeq") + "\r\n" +
		"Contact: <sip:alice@" + phone.address() + ">\r\n" +
		"Content-Type: application/sdp\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
	if err := phone.send(ok); err != nil {
		t.Fatalf("send() error = %v", err)
	}

	// The gateway must ACK the answer, or the client retransmits 200 forever.
	await(t, phone, 3*time.Second, isRequest("ACK"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, answered, _ := fake.snapshot(); len(answered) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, answered, _ := fake.snapshot()
	if len(answered) == 0 || answered[0] != "vocat-in-1" {
		t.Fatalf("vocat answered %v, want [vocat-in-1]", answered)
	}
}

func TestInboundCallIsNotOfferedTwice(t *testing.T) {
	// The poll runs every second and an INVITE takes longer than that to answer,
	// so without a guard the same call would be offered repeatedly.
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	fake.addCall(vocat.Call{
		ID: "vocat-in-1", Number: "+447700900123", Direction: "incoming",
		State: "ringing", StartedAt: time.Now().UTC(),
	})
	await(t, phone, 6*time.Second, isRequest("INVITE"))

	// Watch for a second INVITE over several poll cycles.
	buffer := make([]byte, 8192)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = phone.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		count, _, err := phone.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		message, parseErr := sip.Parse(buffer[:count])
		if parseErr == nil && !message.IsResponse && message.Method == "INVITE" {
			t.Fatal("the same inbound call was offered twice")
		}
	}
}

func TestInboundCallWithNoRegistrationIsLeftAlone(t *testing.T) {
	// The operator may still answer in vocat's own UI, and the plugin's rule
	// engine may have its own plan, so the gateway must not reject the call.
	_, fake := startGateway(t, nil)
	fake.addCall(vocat.Call{
		ID: "vocat-in-1", Number: "+447700900123", Direction: "incoming",
		State: "ringing", StartedAt: time.Now().UTC(),
	})
	time.Sleep(2500 * time.Millisecond)
	if _, _, hungUp := fake.snapshot(); len(hungUp) != 0 {
		t.Fatalf("an unanswerable inbound call was hung up: %v", hungUp)
	}
}

func TestCellularTransportIsNotMappedToSIP(t *testing.T) {
	// The cellular transport returns AT-derived integers with no stable call id,
	// which cannot be mapped to a SIP dialog.
	gateway, fake := startGateway(t, nil)
	phone := registerPhone(t, gateway)
	fake.setTransport("cellular")
	fake.addCall(vocat.Call{
		ID: "vocat-in-1", Number: "+447700900123", Direction: "incoming",
		State: "ringing", StartedAt: time.Now().UTC(),
	})

	buffer := make([]byte, 8192)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = phone.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		count, _, err := phone.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		message, parseErr := sip.Parse(buffer[:count])
		if parseErr == nil && !message.IsResponse && message.Method == "INVITE" {
			t.Fatal("a cellular call was offered over SIP")
		}
	}
	if gateway.Status().ActiveCalls != 0 {
		t.Fatal("a cellular call created a dialog")
	}
}

func TestNewRejectsIncompleteConfiguration(t *testing.T) {
	fake := newFakeVocat()
	defer fake.Close()
	client, err := fake.client()
	if err != nil {
		t.Fatalf("vocat.New() error = %v", err)
	}
	valid := Config{Account: Account{Username: "alice", Password: "p", DeviceID: "ec20"}}

	// Without vocat credentials the gateway could accept a call and then be
	// unable to place it, which is worse than refusing to start.
	if _, err := New(valid, nil, quietLogger()); err == nil {
		t.Fatal("New() must require a vocat client")
	}
	for name, config := range map[string]Config{
		"no username": {Account: Account{Password: "p", DeviceID: "ec20"}},
		"no password": {Account: Account{Username: "alice", DeviceID: "ec20"}},
		"no device":   {Account: Account{Username: "alice", Password: "p"}},
		"bad advertise": {
			AdvertiseIP: "not-an-ip",
			Account:     Account{Username: "alice", Password: "p", DeviceID: "ec20"},
		},
		"bad cidr": {
			AllowedSources: []string{"nonsense"},
			Account:        Account{Username: "alice", Password: "p", DeviceID: "ec20"},
		},
	} {
		if _, err := New(config, client, quietLogger()); err == nil {
			t.Fatalf("%s: New() must fail", name)
		}
	}
	if _, err := New(valid, client, quietLogger()); err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}
}

func TestAllowedSourcesAcceptsBareAddresses(t *testing.T) {
	// An operator naturally types an address, not a /32.
	networks, err := parseCIDRs([]string{"192.168.1.50", "10.0.0.0/8", "", "  "})
	if err != nil {
		t.Fatalf("parseCIDRs() error = %v", err)
	}
	if len(networks) != 2 {
		t.Fatalf("parseCIDRs() = %d networks, want 2", len(networks))
	}
	if !networks[0].Contains(net.ParseIP("192.168.1.50")) {
		t.Fatal("a bare address did not become a single-host rule")
	}
	if networks[0].Contains(net.ParseIP("192.168.1.51")) {
		t.Fatal("a bare address matched a neighbour")
	}
}

func TestStopIsIdempotentAndReleasesResources(t *testing.T) {
	gateway, _ := startGateway(t, nil)
	address := gateway.Status().Address
	gateway.Stop()
	gateway.Stop() // must be safe twice

	if gateway.Status().Running {
		t.Fatal("Status() still reports running after Stop()")
	}
	// The port must be free again, or a restart would fail.
	conn, err := net.ListenUDP("udp", mustResolve(t, address))
	if err != nil {
		t.Fatalf("port %s was not released: %v", address, err)
	}
	_ = conn.Close()
}

func TestDialogNumberExtraction(t *testing.T) {
	for name, testCase := range map[string]struct {
		uri  string
		want string
	}{
		"sip user":     {"sip:10086@vocat", "10086"},
		"plus":         {"sip:+447700900123@vocat", "+447700900123"},
		"tel":          {"tel:+447700900123", "+447700900123"},
		"formatted":    {"sip:+44 7700 900123@vocat", "+447700900123"},
		"star code":    {"sip:*100#@vocat", "*100#"},
		"host only":    {"sip:10086", "10086"},
		"letters gone": {"sip:abc123@vocat", "123"},
	} {
		if got := dialogNumber(testCase.uri); got != testCase.want {
			t.Fatalf("%s: dialogNumber(%q) = %q, want %q", name, testCase.uri, got, testCase.want)
		}
	}
}

func TestValidDialNumberMirrorsVocat(t *testing.T) {
	for _, value := range []string{"10086", "+447700900123", "*100#"} {
		if !validDialNumber(value) {
			t.Fatalf("validDialNumber(%q) = false", value)
		}
	}
	for _, value := range []string{"", "1", "+", strings.Repeat("9", 33)} {
		if validDialNumber(value) {
			t.Fatalf("validDialNumber(%q) = true", value)
		}
	}
}

func TestWithTagReplacesRatherThanDuplicates(t *testing.T) {
	// A retransmission must not produce two tags, which would make the client
	// treat it as a different dialog.
	if got := withTag("<sip:a@b>", "t1"); got != "<sip:a@b>;tag=t1" {
		t.Fatalf("withTag() = %q", got)
	}
	if got := withTag("<sip:a@b>;tag=old", "new"); got != "<sip:a@b>;tag=new" {
		t.Fatalf("withTag() = %q, want the tag replaced", got)
	}
	if got := withTag("<sip:a@b>", ""); got != "<sip:a@b>" {
		t.Fatalf("withTag() with an empty tag = %q", got)
	}
}

func TestURIFromContactUsesTheReachableHost(t *testing.T) {
	// A NAT-bound client's Contact host is unreachable, so the observed target's
	// host is substituted while the user part is kept.
	got := uriFromContact("<sip:alice@192.168.1.50:5060>", "203.0.113.9:41234")
	want := "sip:alice@203.0.113.9:41234"
	if got != want {
		t.Fatalf("uriFromContact() = %q, want %q", got, want)
	}
	// An unparsable Contact still yields something dialable.
	if got := uriFromContact("garbage", "203.0.113.9:41234"); got == "" {
		t.Fatal("uriFromContact() returned an empty URI")
	}
}

func mustResolve(t *testing.T, address string) *net.UDPAddr {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q) error = %v", address, err)
	}
	return resolved
}
