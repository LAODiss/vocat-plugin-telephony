// RTP transport for the SIP gateway.
//
// This is a two-party audio relay, not a general RTP stack: one socket per call,
// one remote peer, G.711 only. Three behaviours are load-bearing and easy to get
// wrong, so they are called out where they happen: symmetric RTP (the phone is
// almost always behind NAT), a bounded jitter buffer that drops rather than
// grows, and refusing packets from an unexpected source.
package rtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// ClockRate is fixed at 8 kHz: both G.711 and vocat's PCM bridge use it, so
	// no resampling ever happens in this gateway.
	ClockRate = 8000
	// FrameSamples is 20 ms, the ptime every softphone defaults to and the
	// packetisation vocat's IMS side uses.
	FrameSamples = 160
	// headerBytes is the fixed RTP header size.
	headerBytes = 12
	// maxPacketBytes bounds a datagram. 20 ms of G.711 is 172 bytes with the
	// header; the slack covers a client using a longer ptime.
	maxPacketBytes = 1500
	// jitterFrames is the receive queue depth: 25 x 20 ms = 500 ms. Beyond this
	// the audio is too late to be useful, so the oldest frame is dropped instead
	// of letting latency grow without bound.
	jitterFrames = 25
)

// Session is one call's RTP endpoint.
type Session struct {
	conn    *net.UDPConn
	payload PayloadType

	mu sync.RWMutex
	// remote is where outbound packets go. It is learned from SDP and then
	// corrected by symmetric RTP, because a phone behind NAT almost never
	// receives on the port it advertised.
	remote *net.UDPAddr
	// expectedHost pins the source address. Learning the port is necessary;
	// accepting a different host would let anyone inject audio into a call.
	expectedHost net.IP
	// symmetricLearned records that the port has been corrected once, so a
	// later stray packet cannot move the stream again.
	symmetricLearned bool

	writeMu   sync.Mutex
	pending   []int16
	sequence  uint16
	timestamp uint32
	ssrc      uint32

	inbound   chan []int16
	closeOnce sync.Once
	closed    chan struct{}

	// dropped counts frames discarded by the jitter policy, surfaced for
	// diagnostics rather than silently lost.
	statsMu  sync.Mutex
	dropped  int
	received int
	sent     int
}

// Options configures a session.
type Options struct {
	// ListenIP is the local address to bind. Empty binds all interfaces.
	ListenIP net.IP
	// Payload is the negotiated codec.
	Payload PayloadType
	// SSRC identifies this stream. Zero picks a random value.
	SSRC uint32
	// Sequence and Timestamp seed the outbound stream. Zero picks random values,
	// which RFC 3550 requires so a stream cannot be trivially predicted.
	Sequence  uint16
	Timestamp uint32
}

// Listen opens an RTP socket on an even port, as RFC 3550 expects, so the
// following odd port stays free for RTCP even though this gateway does not use
// it. Some clients and middleboxes assume the pairing.
func Listen(options Options) (*Session, error) {
	if !options.Payload.Supported() {
		return nil, fmt.Errorf("rtp: unsupported payload type %d", options.Payload)
	}
	conn, err := listenEvenPort(options.ListenIP)
	if err != nil {
		return nil, err
	}
	seed, err := randomSeed()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	session := &Session{
		conn:      conn,
		payload:   options.Payload,
		sequence:  pick16(options.Sequence, seed.sequence),
		timestamp: pick32(options.Timestamp, seed.timestamp),
		ssrc:      pick32(options.SSRC, seed.ssrc),
		inbound:   make(chan []int16, jitterFrames),
		closed:    make(chan struct{}),
	}
	go session.receive()
	return session, nil
}

// listenEvenPort retries until it gets an even port. The kernel assigns from
// the ephemeral range, so a handful of attempts is enough in practice.
func listenEvenPort(ip net.IP) (*net.UDPConn, error) {
	var odd []*net.UDPConn
	defer func() {
		for _, conn := range odd {
			_ = conn.Close()
		}
	}()
	for attempt := 0; attempt < 16; attempt++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("rtp: open socket: %w", err)
		}
		if conn.LocalAddr().(*net.UDPAddr).Port%2 == 0 {
			return conn, nil
		}
		// Hold the odd socket until we have an even one, otherwise the kernel
		// may hand back the same port on the next attempt.
		odd = append(odd, conn)
	}
	return nil, errors.New("rtp: could not obtain an even local port")
}

// LocalPort is the port to advertise in SDP.
func (session *Session) LocalPort() int {
	return session.conn.LocalAddr().(*net.UDPAddr).Port
}

// Payload is the negotiated codec.
func (session *Session) Payload() PayloadType {
	return session.payload
}

// SetRemote points the outbound stream at the address from the peer's SDP.
func (session *Session) SetRemote(host net.IP, port int) error {
	if host == nil || port < 1 || port > 65535 {
		return fmt.Errorf("rtp: invalid remote %v:%d", host, port)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.remote = &net.UDPAddr{IP: append(net.IP(nil), host...), Port: port}
	session.expectedHost = append(net.IP(nil), host...)
	session.symmetricLearned = false
	return nil
}

// Remote reports the current destination, for diagnostics.
func (session *Session) Remote() string {
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.remote == nil {
		return ""
	}
	return session.remote.String()
}

// Ready reports whether a remote has been negotiated.
func (session *Session) Ready() bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.remote != nil
}

// Write packetises PCM into 20 ms RTP packets. Partial frames are buffered, so
// a caller may hand over any batch size.
func (session *Session) Write(samples []int16) error {
	session.mu.RLock()
	var remote *net.UDPAddr
	if session.remote != nil {
		copied := *session.remote
		remote = &copied
	}
	session.mu.RUnlock()
	if remote == nil {
		// Not yet negotiated. Dropping is correct: queueing would burst stale
		// audio at the far end the moment SDP arrives.
		return nil
	}

	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	session.pending = append(session.pending, samples...)
	for len(session.pending) >= FrameSamples {
		frame := session.pending[:FrameSamples]
		packet := make([]byte, headerBytes+FrameSamples)
		packet[0] = 0x80 // version 2, no padding, no extension, no CSRC
		packet[1] = byte(session.payload)
		binary.BigEndian.PutUint16(packet[2:4], session.sequence)
		binary.BigEndian.PutUint32(packet[4:8], session.timestamp)
		binary.BigEndian.PutUint32(packet[8:12], session.ssrc)
		copy(packet[headerBytes:], Encode(session.payload, frame))

		if _, err := session.conn.WriteToUDP(packet, remote); err != nil {
			return fmt.Errorf("rtp: send: %w", err)
		}
		session.pending = session.pending[FrameSamples:]
		session.sequence++
		session.timestamp += FrameSamples
		session.statsMu.Lock()
		session.sent++
		session.statsMu.Unlock()
	}
	return nil
}

// Read returns the next batch of inbound samples, blocking until one arrives,
// the deadline passes, or the session closes.
func (session *Session) Read(timeout time.Duration) ([]int16, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-session.closed:
		return nil, io.EOF
	case samples := <-session.inbound:
		return samples, nil
	case <-timer.C:
		// A timeout is silence, not a failure: the caller decides whether that
		// means the call has gone quiet or died.
		return nil, nil
	}
}

func (session *Session) receive() {
	buffer := make([]byte, maxPacketBytes)
	for {
		count, source, err := session.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		samples, ok := session.decodePacket(buffer[:count], source)
		if !ok {
			continue
		}
		session.statsMu.Lock()
		session.received++
		session.statsMu.Unlock()

		select {
		case session.inbound <- samples:
		default:
			// The queue is full: drop the oldest frame so latency stays bounded.
			// Growing the buffer would trade a gap for an ever-increasing delay,
			// which is worse on a live call.
			select {
			case <-session.inbound:
			default:
			}
			select {
			case session.inbound <- samples:
			default:
			}
			session.statsMu.Lock()
			session.dropped++
			session.statsMu.Unlock()
		}
	}
}

// decodePacket validates a datagram and returns its samples.
func (session *Session) decodePacket(packet []byte, source *net.UDPAddr) ([]int16, bool) {
	if len(packet) < headerBytes {
		return nil, false
	}
	if packet[0]>>6 != 2 {
		return nil, false // not RTP version 2
	}
	if PayloadType(packet[1]&0x7f) != session.payload {
		// A different payload type mid-call means the peer changed codec without
		// re-negotiating; decoding it as G.711 would produce noise.
		return nil, false
	}

	session.mu.Lock()
	expected := session.expectedHost
	if expected != nil && !expected.Equal(source.IP) {
		// Only the port may be learned. A different host is either a stray
		// packet or an injection attempt.
		session.mu.Unlock()
		return nil, false
	}
	// Symmetric RTP: a phone behind NAT sends from a different port than the one
	// its SDP advertised, and replies must go to the port we actually see.
	if session.remote != nil && !session.symmetricLearned && session.remote.Port != source.Port {
		session.remote = &net.UDPAddr{IP: append(net.IP(nil), source.IP...), Port: source.Port}
		session.symmetricLearned = true
	}
	session.mu.Unlock()

	offset := headerBytes + int(packet[0]&0x0f)*4 // CSRC list
	if packet[0]&0x10 != 0 {                      // extension header
		if len(packet) < offset+4 {
			return nil, false
		}
		offset += 4 + int(binary.BigEndian.Uint16(packet[offset+2:offset+4]))*4
	}
	if offset >= len(packet) {
		return nil, false
	}
	payload := packet[offset:]
	if packet[0]&0x20 != 0 { // padding
		padding := int(payload[len(payload)-1])
		if padding <= 0 || padding > len(payload) {
			return nil, false
		}
		payload = payload[:len(payload)-padding]
	}
	if len(payload) == 0 {
		return nil, false
	}
	return Decode(session.payload, payload), true
}

// Stats reports packet counters for the panel.
type Stats struct {
	Sent     int `json:"sent"`
	Received int `json:"received"`
	Dropped  int `json:"dropped"`
}

func (session *Session) Stats() Stats {
	session.statsMu.Lock()
	defer session.statsMu.Unlock()
	return Stats{Sent: session.sent, Received: session.received, Dropped: session.dropped}
}

// Close releases the socket. Safe to call twice.
func (session *Session) Close() {
	session.closeOnce.Do(func() {
		close(session.closed)
		_ = session.conn.Close()
	})
}

type seeds struct {
	sequence  uint16
	timestamp uint32
	ssrc      uint32
}

func pick16(configured, random uint16) uint16 {
	if configured != 0 {
		return configured
	}
	return random
}

func pick32(configured, random uint32) uint32 {
	if configured != 0 {
		return configured
	}
	return random
}
