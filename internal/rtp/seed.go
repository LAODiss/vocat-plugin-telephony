package rtp

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// randomSeed produces the initial sequence number, timestamp and SSRC.
//
// RFC 3550 requires these to be unpredictable: a guessable stream can be hijacked
// by an off-path attacker who only needs to land packets in the right window.
func randomSeed() (seeds, error) {
	buffer := make([]byte, 10)
	if _, err := io.ReadFull(cryptorand.Reader, buffer); err != nil {
		return seeds{}, fmt.Errorf("rtp: seed random state: %w", err)
	}
	seed := seeds{
		sequence:  binary.BigEndian.Uint16(buffer[0:2]),
		timestamp: binary.BigEndian.Uint32(buffer[2:6]),
		ssrc:      binary.BigEndian.Uint32(buffer[6:10]),
	}
	// Zero is used as "unset" by the options, so nudge it away rather than
	// letting a random zero silently mean "pick again".
	if seed.sequence == 0 {
		seed.sequence = 1
	}
	if seed.timestamp == 0 {
		seed.timestamp = 1
	}
	if seed.ssrc == 0 {
		seed.ssrc = 1
	}
	return seed, nil
}
