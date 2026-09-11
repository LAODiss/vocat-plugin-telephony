package sipgw

import (
	"net"
	"strings"
	"testing"

	"vocat-plugin-telephony/internal/rtp"
)

// linphoneOffer is the shape a real softphone sends: several codecs in
// preference order, telephone-event, and attributes this gateway ignores.
const linphoneOffer = "v=0\r\n" +
	"o=alice 123 456 IN IP4 192.168.1.50\r\n" +
	"s=Talk\r\n" +
	"c=IN IP4 192.168.1.50\r\n" +
	"t=0 0\r\n" +
	"m=audio 7078 RTP/AVP 96 8 0 101\r\n" +
	"a=rtpmap:96 opus/48000/2\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-15\r\n" +
	"a=ptime:20\r\n"

func TestParseSDPPrefersThePeerCodecOrder(t *testing.T) {
	// The phone lists opus first, then PCMA. We cannot do opus, so PCMA must win
	// over PCMU — honouring the peer's order rather than our own preference,
	// because a client's first choice is its best-tested path.
	media, err := parseSDP([]byte(linphoneOffer))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	if media.Payload != rtp.PayloadPCMA {
		t.Fatalf("Payload = %s, want PCMA (first supported in the peer's order)", media.Payload.Name())
	}
	if media.Port != 7078 {
		t.Fatalf("Port = %d, want 7078", media.Port)
	}
	if !media.Address.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("Address = %v", media.Address)
	}
}

func TestParseSDPPicksPCMUWhenListedFirst(t *testing.T) {
	body := "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 4000 RTP/AVP 0 8\r\n"
	media, err := parseSDP([]byte(body))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	if media.Payload != rtp.PayloadPCMU {
		t.Fatalf("Payload = %s, want PCMU", media.Payload.Name())
	}
}

func TestParseSDPUsesStaticPayloadTypesWithoutRtpmap(t *testing.T) {
	// Payload types 0 and 8 are statically assigned; many clients omit rtpmap.
	body := "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 4000 RTP/AVP 8\r\n"
	media, err := parseSDP([]byte(body))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	if media.Payload != rtp.PayloadPCMA {
		t.Fatalf("Payload = %s, want PCMA", media.Payload.Name())
	}
}

func TestParseSDPMediaLevelAddressWins(t *testing.T) {
	// A session-level c= is a default; a media-level one overrides it. Getting
	// this backwards sends audio to the wrong host.
	body := "v=0\r\nc=IN IP4 1.1.1.1\r\n" +
		"m=audio 5000 RTP/AVP 8\r\nc=IN IP4 2.2.2.2\r\na=rtpmap:8 PCMA/8000\r\n"
	media, err := parseSDP([]byte(body))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	if !media.Address.Equal(net.ParseIP("2.2.2.2")) {
		t.Fatalf("Address = %v, want the media-level address", media.Address)
	}
}

func TestParseSDPIgnoresNonAudioStreams(t *testing.T) {
	// A video stream's port and codecs must not be mistaken for the audio ones.
	body := "v=0\r\nc=IN IP4 10.0.0.5\r\n" +
		"m=video 9000 RTP/AVP 99\r\na=rtpmap:99 H264/90000\r\n" +
		"m=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
	media, err := parseSDP([]byte(body))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	if media.Port != 4000 || media.Payload != rtp.PayloadPCMA {
		t.Fatalf("picked the wrong stream: %+v", media)
	}
}

func TestParseSDPReadsDirectionAttributes(t *testing.T) {
	// A phone putting a call on hold sends sendonly/inactive. Without this the
	// gateway would read the resulting silence as a broken audio path.
	for attribute, check := range map[string]func(mediaDescription) bool{
		"a=sendonly\r\n": func(media mediaDescription) bool { return media.SendOnly },
		"a=recvonly\r\n": func(media mediaDescription) bool { return media.RecvOnly },
		"a=inactive\r\n": func(media mediaDescription) bool { return media.Inactive },
	} {
		body := "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 4000 RTP/AVP 8\r\n" + attribute
		media, err := parseSDP([]byte(body))
		if err != nil {
			t.Fatalf("%s: parseSDP() error = %v", strings.TrimSpace(attribute), err)
		}
		if !check(media) {
			t.Fatalf("%s was not recorded: %+v", strings.TrimSpace(attribute), media)
		}
	}
}

func TestParseSDPRejectsUnusableOffers(t *testing.T) {
	for name, body := range map[string]string{
		"empty":           "",
		"no address":      "v=0\r\nm=audio 4000 RTP/AVP 8\r\n",
		"declined stream": "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 0 RTP/AVP 8\r\n",
		"no supported codec": "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 4000 RTP/AVP 96\r\n" +
			"a=rtpmap:96 opus/48000/2\r\n",
		"dtmf only": "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 4000 RTP/AVP 101\r\n" +
			"a=rtpmap:101 telephone-event/8000\r\n",
		"no audio stream": "v=0\r\nc=IN IP4 10.0.0.5\r\nm=video 9000 RTP/AVP 99\r\n",
	} {
		if _, err := parseSDP([]byte(body)); err == nil {
			t.Fatalf("%s: parseSDP() must fail so the caller can answer 488", name)
		}
	}
}

func TestBuildSDPOmitsTelephoneEvent(t *testing.T) {
	// vocat has no DTMF send path. Announcing RFC 4733 would make the phone send
	// named events into a void; without it, clients fall back to in-band tones
	// that at least traverse G.711.
	body := string(buildSDP(net.ParseIP("192.168.1.10"), 40000, rtp.PayloadPCMA, 1))
	if strings.Contains(strings.ToLower(body), "telephone-event") {
		t.Fatalf("SDP announces DTMF it cannot send:\n%s", body)
	}
	for _, want := range []string{
		"v=0\r\n",
		"c=IN IP4 192.168.1.10\r\n",
		"m=audio 40000 RTP/AVP 8\r\n",
		"a=rtpmap:8 PCMA/8000\r\n",
		"a=ptime:20\r\n",
		"a=sendrecv\r\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("SDP missing %q:\n%s", want, body)
		}
	}
	if !strings.HasSuffix(body, "\r\n") {
		t.Fatal("SDP must end with CRLF")
	}
}

func TestBuildSDPAnnouncesOnlyTheNegotiatedCodec(t *testing.T) {
	// An answer must not re-offer codecs; listing both would let the peer switch
	// mid-call to one the RTP session is not decoding.
	body := string(buildSDP(net.ParseIP("10.0.0.1"), 5004, rtp.PayloadPCMU, 7))
	if !strings.Contains(body, "m=audio 5004 RTP/AVP 0\r\n") {
		t.Fatalf("wrong m= line:\n%s", body)
	}
	if strings.Contains(body, "PCMA") {
		t.Fatalf("answer offered a second codec:\n%s", body)
	}
}

func TestBuildSDPHandlesIPv6(t *testing.T) {
	body := string(buildSDP(net.ParseIP("2001:db8::1"), 40000, rtp.PayloadPCMA, 1))
	if !strings.Contains(body, "c=IN IP6 2001:db8::1\r\n") {
		t.Fatalf("IPv6 connection line wrong:\n%s", body)
	}
	if strings.Contains(body, "IN IP4") {
		t.Fatalf("IPv4 family leaked into an IPv6 answer:\n%s", body)
	}
}

func TestBuildSDPRoundTripsThroughTheParser(t *testing.T) {
	// Our own answer must be readable by our own parser, or a re-INVITE would
	// fail in a way that is hard to attribute.
	body := buildSDP(net.ParseIP("192.168.1.10"), 40000, rtp.PayloadPCMU, 42)
	media, err := parseSDP(body)
	if err != nil {
		t.Fatalf("our own SDP does not parse: %v", err)
	}
	if media.Port != 40000 || media.Payload != rtp.PayloadPCMU {
		t.Fatalf("round trip changed the stream: %+v", media)
	}
	if !media.Address.Equal(net.ParseIP("192.168.1.10")) {
		t.Fatalf("round trip changed the address: %v", media.Address)
	}
}
