// Package media bridges vocat's call audio WebSocket.
//
// vocat exposes an active call's audio as a WebSocket carrying raw
// little-endian signed 16-bit mono PCM at 8 kHz in both directions, and it
// accepts a non-browser client because coder/websocket lets a request with no
// Origin header through. That is the only way a plugin can touch call audio:
// there is no RTP-level hook and no recording API.
//
// The consequence is worth stating plainly. What arrives here is vocat's
// WebSocket downlink, not the raw RTP stream, so any packet vocat's jitter
// buffer dropped is already gone. Recording through this path is good enough to
// keep a message, but it is not a faithful capture of the wire.
package media

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vocat-plugin-telephony/internal/wav"
)

const (
	// FrameSamples is 20 ms at 8 kHz, the RTP packetisation vocat uses.
	FrameSamples = 160
	// maxMessageBytes mirrors vocat's own read limit on this socket.
	maxMessageBytes = 16 << 10
)

// Session is one open audio bridge for a call.
type Session struct {
	connection *websocket.Conn

	mu     sync.Mutex
	closed bool
}

// Dial connects to a call's audio. The HTTP client must carry the authenticated
// cookie jar, pinned TLS and HTTP/1.1, because vocat's upgrade handler needs a
// hijackable connection and HTTP/2 does not provide one.
//
// Origin is deliberately not set: vocat passes a request with no Origin, and a
// wrong one would be rejected.
func Dial(ctx context.Context, mediaURL string, client *http.Client) (*Session, error) {
	if strings.TrimSpace(mediaURL) == "" {
		return nil, errors.New("media: URL is required")
	}
	if client == nil {
		return nil, errors.New("media: an authenticated HTTP client is required")
	}
	connection, _, err := websocket.Dial(ctx, mediaURL, &websocket.DialOptions{
		HTTPClient:      client,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("media: connect call audio: %w", err)
	}
	connection.SetReadLimit(maxMessageBytes)
	return &Session{connection: connection}, nil
}

// Read returns the next batch of downlink samples, or an error when the socket
// closes. A non-binary, empty or odd-length message is skipped rather than
// treated as a failure, matching how vocat itself filters the uplink.
func (session *Session) Read(ctx context.Context) ([]int16, error) {
	for {
		messageType, payload, err := session.connection.Read(ctx)
		if err != nil {
			return nil, err
		}
		if messageType != websocket.MessageBinary || len(payload) < 2 {
			continue
		}
		usable := len(payload) - len(payload)%2
		samples := make([]int16, usable/2)
		for index := range samples {
			samples[index] = int16(binary.LittleEndian.Uint16(payload[index*2:]))
		}
		return samples, nil
	}
}

// Write sends samples into the call.
func (session *Session) Write(ctx context.Context, samples []int16) error {
	if len(samples) == 0 {
		return nil
	}
	payload := make([]byte, len(samples)*2)
	for index, sample := range samples {
		binary.LittleEndian.PutUint16(payload[index*2:], uint16(sample))
	}
	return session.connection.Write(ctx, websocket.MessageBinary, payload)
}

// PlayFile streams a WAV file into the call in real time. Sending it as fast as
// possible would overrun the far end's jitter buffer, so frames are paced.
func (session *Session) PlayFile(ctx context.Context, path string) error {
	samples, err := wav.ReadMono(path)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second * FrameSamples / wav.SampleRate)
	defer ticker.Stop()
	for offset := 0; offset < len(samples); offset += FrameSamples {
		end := offset + FrameSamples
		if end > len(samples) {
			end = len(samples)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := session.Write(ctx, samples[offset:end]); err != nil {
			return fmt.Errorf("media: play %s: %w", path, err)
		}
	}
	return nil
}

// Close ends the bridge. Safe to call twice.
func (session *Session) Close() {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	session.closed = true
	_ = session.connection.Close(websocket.StatusNormalClosure, "closed")
}

// IsClosed reports whether the far end or the caller has closed the socket.
func IsClosed(err error) bool {
	return err != nil && websocket.CloseStatus(err) != -1
}

// Voiced is a crude energy gate, used to detect silence. It only has to
// distinguish "someone is talking" from "the line is quiet"; anything more
// would be guessing at codec behaviour.
func Voiced(frame []int16) bool {
	const threshold = 500
	var peak int32
	for _, sample := range frame {
		value := int32(sample)
		if value < 0 {
			value = -value
		}
		if value > peak {
			peak = value
		}
	}
	return peak > threshold
}
