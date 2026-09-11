package rtp

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func loopback() net.IP { return net.IPv4(127, 0, 0, 1) }

func openSession(t *testing.T, payload PayloadType) *Session {
	t.Helper()
	session, err := Listen(Options{ListenIP: loopback(), Payload: payload})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(session.Close)
	return session
}

func TestListenUsesAnEvenPort(t *testing.T) {
	// RFC 3550 pairs RTP with RTCP on the following odd port. Some clients and
	// middleboxes assume the pairing even when RTCP is unused.
	for attempt := 0; attempt < 5; attempt++ {
		session := openSession(t, PayloadPCMA)
		if session.LocalPort()%2 != 0 {
			t.Fatalf("LocalPort() = %d, want an even port", session.LocalPort())
		}
	}
}

func TestBidirectionalAudio(t *testing.T) {
	left := openSession(t, PayloadPCMA)
	right := openSession(t, PayloadPCMA)
	if err := left.SetRemote(loopback(), right.LocalPort()); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	if err := right.SetRemote(loopback(), left.LocalPort()); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}

	tone := make([]int16, FrameSamples)
	for index := range tone {
		tone[index] = int16(1000 + index)
	}
	if err := left.Write(tone); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	received, err := right.Read(2 * time.Second)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(received) != FrameSamples {
		t.Fatalf("received %d samples, want %d", len(received), FrameSamples)
	}
	// G.711 is lossy, so compare within the codec's error at this amplitude.
	for index := range received {
		difference := int(received[index]) - int(tone[index])
		if difference < 0 {
			difference = -difference
		}
		if difference > 200 {
			t.Fatalf("sample %d: got %d want ~%d", index, received[index], tone[index])
		}
	}
	if stats := left.Stats(); stats.Sent != 1 {
		t.Fatalf("sender stats = %+v", stats)
	}
	if stats := right.Stats(); stats.Received != 1 {
		t.Fatalf("receiver stats = %+v", stats)
	}
}

func TestPartialFramesAreBuffered(t *testing.T) {
	// A caller may hand over any batch size; only whole 20 ms frames go on the
	// wire, so a partial frame must be held rather than padded.
	sender := openSession(t, PayloadPCMU)
	receiver := openSession(t, PayloadPCMU)
	if err := sender.SetRemote(loopback(), receiver.LocalPort()); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	if err := sender.Write(make([]int16, 100)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if stats := sender.Stats(); stats.Sent != 0 {
		t.Fatalf("a partial frame was sent: %+v", stats)
	}
	// The remaining 60 samples complete the frame.
	if err := sender.Write(make([]int16, 60)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if stats := sender.Stats(); stats.Sent != 1 {
		t.Fatalf("completed frame was not sent: %+v", stats)
	}
}

func TestWriteBeforeNegotiationIsDropped(t *testing.T) {
	// Queueing pre-negotiation audio would burst stale sound at the far end the
	// moment SDP arrives.
	session := openSession(t, PayloadPCMA)
	if session.Ready() {
		t.Fatal("Ready() must be false before SetRemote")
	}
	if err := session.Write(make([]int16, FrameSamples*3)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if stats := session.Stats(); stats.Sent != 0 {
		t.Fatalf("audio was sent with no remote: %+v", stats)
	}
}

func TestSymmetricRTPLearnsTheRealPort(t *testing.T) {
	// A phone behind NAT sends from a different port than its SDP advertised.
	// Replies must go to the port actually observed, or the caller hears nothing.
	gateway := openSession(t, PayloadPCMA)
	phone, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer phone.Close()

	// SDP claims a port the phone does not actually use.
	wrongPort := phone.LocalAddr().(*net.UDPAddr).Port + 1
	if wrongPort > 65535 {
		wrongPort = phone.LocalAddr().(*net.UDPAddr).Port - 1
	}
	if err := gateway.SetRemote(loopback(), wrongPort); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}

	// The phone sends from its real port.
	if _, err := phone.WriteToUDP(
		buildPacket(PayloadPCMA, 1, 160, 0x1234, make([]byte, FrameSamples)),
		&net.UDPAddr{IP: loopback(), Port: gateway.LocalPort()},
	); err != nil {
		t.Fatalf("phone WriteToUDP() error = %v", err)
	}
	if _, err := gateway.Read(2 * time.Second); err != nil {
		t.Fatalf("gateway Read() error = %v", err)
	}

	realPort := phone.LocalAddr().(*net.UDPAddr).Port
	if remote := gateway.Remote(); remote != net.JoinHostPort("127.0.0.1", itoa(realPort)) {
		t.Fatalf("Remote() = %q, want the observed port %d", remote, realPort)
	}

	// Outbound audio must now reach the phone.
	if err := gateway.Write(make([]int16, FrameSamples)); err != nil {
		t.Fatalf("gateway Write() error = %v", err)
	}
	_ = phone.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1500)
	if _, _, err := phone.ReadFromUDP(buffer); err != nil {
		t.Fatalf("phone did not receive audio after symmetric learning: %v", err)
	}
}

func TestPacketsFromAnotherHostAreRefused(t *testing.T) {
	// Learning the port is necessary; accepting a different host would let anyone
	// inject audio into a live call.
	session := openSession(t, PayloadPCMA)
	// Pin the expected host to an address the sender will not use.
	if err := session.SetRemote(net.IPv4(127, 0, 0, 2), 40000); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	attacker, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer attacker.Close()
	if _, err := attacker.WriteToUDP(
		buildPacket(PayloadPCMA, 1, 160, 0x9999, make([]byte, FrameSamples)),
		&net.UDPAddr{IP: loopback(), Port: session.LocalPort()},
	); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
	samples, err := session.Read(300 * time.Millisecond)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if samples != nil {
		t.Fatal("audio from an unexpected host was accepted")
	}
	if stats := session.Stats(); stats.Received != 0 {
		t.Fatalf("stats counted a refused packet: %+v", stats)
	}
}

func TestMalformedPacketsAreIgnored(t *testing.T) {
	session := openSession(t, PayloadPCMA)
	if err := session.SetRemote(loopback(), 40000); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer sender.Close()
	target := &net.UDPAddr{IP: loopback(), Port: session.LocalPort()}

	cases := map[string][]byte{
		"too short":     {0x80, 0x08},
		"wrong version": append([]byte{0x40, 0x08, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 160)...),
		"wrong payload": buildPacket(PayloadPCMU, 1, 160, 1, make([]byte, 160)),
		"header only":   buildPacket(PayloadPCMA, 1, 160, 1, nil),
		"bad padding":   badPaddingPacket(),
	}
	for name, packet := range cases {
		if _, err := sender.WriteToUDP(packet, target); err != nil {
			t.Fatalf("%s: WriteToUDP() error = %v", name, err)
		}
	}
	samples, err := session.Read(300 * time.Millisecond)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if samples != nil {
		t.Fatal("a malformed packet was decoded")
	}
}

func TestExtensionHeaderIsSkipped(t *testing.T) {
	// Clients do send extensions; treating the extension words as audio would
	// produce a click on every packet.
	session := openSession(t, PayloadPCMA)
	if err := session.SetRemote(loopback(), 40000); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer sender.Close()

	audio := make([]byte, FrameSamples)
	for index := range audio {
		audio[index] = 0xD5 // A-law silence
	}
	packet := buildPacket(PayloadPCMA, 5, 800, 0x2222, audio)
	packet[0] |= 0x10 // extension present
	// Insert a 1-word extension between the header and the payload.
	extension := []byte{0xBE, 0xDE, 0x00, 0x01, 0, 0, 0, 0}
	withExtension := append(append(packet[:headerBytes:headerBytes], extension...), audio...)

	if _, err := sender.WriteToUDP(withExtension, &net.UDPAddr{IP: loopback(), Port: session.LocalPort()}); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
	samples, err := session.Read(2 * time.Second)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(samples) != FrameSamples {
		t.Fatalf("got %d samples, want %d (extension not skipped correctly)", len(samples), FrameSamples)
	}
	for index, sample := range samples {
		if abs(int(sample)) > 16 {
			t.Fatalf("sample %d = %d, want silence — extension bytes leaked into audio", index, sample)
		}
	}
}

func TestJitterBufferDropsOldestInsteadOfGrowing(t *testing.T) {
	// Latency must stay bounded. Growing the queue trades a brief gap for an
	// ever-increasing delay, which is worse on a live call.
	session := openSession(t, PayloadPCMA)
	if err := session.SetRemote(loopback(), 40000); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer sender.Close()
	target := &net.UDPAddr{IP: loopback(), Port: session.LocalPort()}

	// Flood well past the queue depth without reading.
	for index := 0; index < jitterFrames*3; index++ {
		packet := buildPacket(PayloadPCMA, uint16(index+1), uint32(index*160), 0x3333, make([]byte, FrameSamples))
		if _, err := sender.WriteToUDP(packet, target); err != nil {
			t.Fatalf("WriteToUDP() error = %v", err)
		}
	}
	// Give the receive goroutine time to drain the socket.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if session.Stats().Dropped > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := session.Stats()
	if stats.Dropped == 0 {
		t.Fatalf("no frames were dropped under flood: %+v", stats)
	}
	// The queue itself is what must stay bounded. Counting frames read is the
	// wrong check: the receive goroutine keeps draining the socket while the
	// reader consumes, so the total readable is bounded by what was sent, not by
	// the queue depth.
	if cap(session.inbound) != jitterFrames {
		t.Fatalf("queue capacity = %d, want %d", cap(session.inbound), jitterFrames)
	}
	if length := len(session.inbound); length > jitterFrames {
		t.Fatalf("queue holds %d frames, above its %d bound", length, jitterFrames)
	}
	// Every frame that survived must still be a whole frame; a drop must not
	// leave a truncated one behind.
	for {
		samples, err := session.Read(100 * time.Millisecond)
		if err != nil || samples == nil {
			break
		}
		if len(samples) != FrameSamples {
			t.Fatalf("read a %d-sample frame, want %d", len(samples), FrameSamples)
		}
	}
}

func TestReadTimeoutIsNotAnError(t *testing.T) {
	// A quiet line is normal; the caller decides whether silence means the call
	// died.
	session := openSession(t, PayloadPCMA)
	samples, err := session.Read(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Read() on a silent session error = %v", err)
	}
	if samples != nil {
		t.Fatal("Read() returned samples with no traffic")
	}
}

func TestReadAfterCloseReportsEOF(t *testing.T) {
	session, err := Listen(Options{ListenIP: loopback(), Payload: PayloadPCMA})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	session.Close()
	session.Close() // must be safe twice
	if _, err := session.Read(time.Second); err != io.EOF {
		t.Fatalf("Read() after Close() = %v, want io.EOF", err)
	}
}

func TestSetRemoteRejectsInvalidInput(t *testing.T) {
	session := openSession(t, PayloadPCMA)
	for name, testCase := range map[string]struct {
		host net.IP
		port int
	}{
		"nil host":  {nil, 5004},
		"zero port": {loopback(), 0},
		"high port": {loopback(), 70000},
	} {
		if err := session.SetRemote(testCase.host, testCase.port); err == nil {
			t.Fatalf("%s: SetRemote() must fail", name)
		}
	}
}

func TestListenRejectsUnsupportedPayload(t *testing.T) {
	if _, err := Listen(Options{ListenIP: loopback(), Payload: PayloadType(99)}); err == nil {
		t.Fatal("Listen() must refuse a codec it cannot transcode")
	}
}

func TestSequenceAndTimestampAdvancePerFrame(t *testing.T) {
	sender := openSession(t, PayloadPCMA)
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback(), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer receiver.Close()
	if err := sender.SetRemote(loopback(), receiver.LocalAddr().(*net.UDPAddr).Port); err != nil {
		t.Fatalf("SetRemote() error = %v", err)
	}
	if err := sender.Write(make([]int16, FrameSamples*3)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var sequences []uint16
	var timestamps []uint32
	var ssrcs []uint32
	buffer := make([]byte, 1500)
	for index := 0; index < 3; index++ {
		_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
		count, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("packet %d: ReadFromUDP() error = %v", index, err)
		}
		if count != headerBytes+FrameSamples {
			t.Fatalf("packet %d has %d bytes, want %d", index, count, headerBytes+FrameSamples)
		}
		sequences = append(sequences, binary.BigEndian.Uint16(buffer[2:4]))
		timestamps = append(timestamps, binary.BigEndian.Uint32(buffer[4:8]))
		ssrcs = append(ssrcs, binary.BigEndian.Uint32(buffer[8:12]))
	}
	for index := 1; index < 3; index++ {
		if sequences[index] != sequences[index-1]+1 {
			t.Fatalf("sequence did not advance by one: %v", sequences)
		}
		if timestamps[index] != timestamps[index-1]+FrameSamples {
			t.Fatalf("timestamp did not advance by the frame size: %v", timestamps)
		}
		if ssrcs[index] != ssrcs[0] {
			t.Fatalf("SSRC changed mid-stream: %v", ssrcs)
		}
	}
}

func TestSeedsAreRandomAndNonZero(t *testing.T) {
	// RFC 3550 requires unpredictable initial state; a guessable stream can be
	// hijacked by an off-path attacker.
	first, err := randomSeed()
	if err != nil {
		t.Fatalf("randomSeed() error = %v", err)
	}
	second, err := randomSeed()
	if err != nil {
		t.Fatalf("randomSeed() error = %v", err)
	}
	if first == second {
		t.Fatal("two seeds were identical")
	}
	if first.sequence == 0 || first.timestamp == 0 || first.ssrc == 0 {
		t.Fatalf("seed contains a zero, which the options treat as unset: %+v", first)
	}
}

func buildPacket(payload PayloadType, sequence uint16, timestamp, ssrc uint32, audio []byte) []byte {
	packet := make([]byte, headerBytes+len(audio))
	packet[0] = 0x80
	packet[1] = byte(payload)
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	copy(packet[headerBytes:], audio)
	return packet
}

func badPaddingPacket() []byte {
	packet := buildPacket(PayloadPCMA, 1, 160, 1, make([]byte, 4))
	packet[0] |= 0x20            // padding flag
	packet[len(packet)-1] = 0xFF // padding longer than the payload
	return packet
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
