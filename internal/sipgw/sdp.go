// SDP handling for the gateway.
//
// Only what a two-party G.711 call needs: one audio stream, one codec, an
// address and a port. Anything else in an offer is ignored rather than rejected,
// because softphones attach video, DTLS and ICE attributes freely and refusing
// them would fail calls that would otherwise work.
package sipgw

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"vocat-plugin-telephony/internal/rtp"
)

// mediaDescription is the part of an SDP body this gateway acts on.
type mediaDescription struct {
	Address net.IP
	Port    int
	Payload rtp.PayloadType
	// SendOnly and RecvOnly record a direction attribute, so a call held by the
	// phone is not mistaken for a broken audio path.
	SendOnly bool
	RecvOnly bool
	Inactive bool
}

// parseSDP extracts the audio stream, choosing the first G.711 codec the peer
// offered. Preferring the peer's order matters: a phone lists its preferred
// codec first, and overriding that choice tends to expose the worse-tested path
// in its own stack.
func parseSDP(body []byte) (mediaDescription, error) {
	if len(body) == 0 {
		return mediaDescription{}, errors.New("sdp: empty body")
	}
	var (
		sessionAddress net.IP
		media          mediaDescription
		inAudio        bool
		formats        []string
		rtpmap         = map[int]string{}
	)
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		value := line[2:]
		switch line[0] {
		case 'c':
			// c= may appear at session level and again per media stream; the
			// media-level one wins.
			fields := strings.Fields(value)
			if len(fields) >= 3 {
				address := net.ParseIP(strings.Split(fields[2], "/")[0])
				if inAudio {
					media.Address = address
				} else {
					sessionAddress = address
				}
			}
		case 'm':
			fields := strings.Fields(value)
			inAudio = len(fields) >= 4 &&
				strings.EqualFold(fields[0], "audio") &&
				strings.HasPrefix(strings.ToUpper(fields[2]), "RTP/AVP")
			if !inAudio {
				continue
			}
			port, err := strconv.Atoi(strings.Split(fields[1], "/")[0])
			if err != nil {
				return mediaDescription{}, fmt.Errorf("sdp: bad audio port %q", fields[1])
			}
			media.Port = port
			formats = append([]string(nil), fields[3:]...)
		case 'a':
			if !inAudio {
				continue
			}
			lower := strings.ToLower(value)
			switch {
			case strings.HasPrefix(lower, "rtpmap:"):
				parts := strings.Fields(value[len("rtpmap:"):])
				if len(parts) == 2 {
					if number, err := strconv.Atoi(parts[0]); err == nil {
						rtpmap[number] = strings.ToUpper(strings.Split(parts[1], "/")[0])
					}
				}
			case lower == "sendonly":
				media.SendOnly = true
			case lower == "recvonly":
				media.RecvOnly = true
			case lower == "inactive":
				media.Inactive = true
			}
		}
	}
	if media.Address == nil {
		media.Address = sessionAddress
	}
	if media.Address == nil {
		return mediaDescription{}, errors.New("sdp: no connection address")
	}
	if media.Port < 1 || media.Port > 65535 {
		// Port 0 is how a peer declines a stream; report it plainly so the caller
		// answers 488 instead of dialling nowhere.
		return mediaDescription{}, fmt.Errorf("sdp: audio port %d is not usable", media.Port)
	}

	payload, ok := pickPayload(formats, rtpmap)
	if !ok {
		return mediaDescription{}, errors.New("sdp: no supported G.711 codec offered")
	}
	media.Payload = payload
	return media, nil
}

// pickPayload walks the peer's format list in order and returns the first
// G.711 codec. Static payload types 0 and 8 need no rtpmap, but a peer may also
// declare them dynamically, so both paths are checked.
func pickPayload(formats []string, rtpmap map[int]string) (rtp.PayloadType, bool) {
	for _, format := range formats {
		number, err := strconv.Atoi(format)
		if err != nil {
			continue
		}
		name := rtpmap[number]
		if name == "" {
			switch number {
			case 0:
				name = "PCMU"
			case 8:
				name = "PCMA"
			}
		}
		switch name {
		case "PCMA":
			return rtp.PayloadPCMA, true
		case "PCMU":
			return rtp.PayloadPCMU, true
		}
	}
	return 0, false
}

// buildSDP renders an answer or offer for one G.711 stream.
//
// telephone-event is deliberately absent. vocat has no DTMF send path, so
// announcing RFC 4733 would make a phone send named events into a void; without
// it, clients fall back to in-band tones, which at least traverse G.711.
func buildSDP(address net.IP, port int, payload rtp.PayloadType, sessionID int64) []byte {
	family := "IP4"
	if address.To4() == nil {
		family = "IP6"
	}
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d %d IN %s %s", sessionID, sessionID, family, address.String()),
		"s=vocat",
		fmt.Sprintf("c=IN %s %s", family, address.String()),
		"t=0 0",
		fmt.Sprintf("m=audio %d RTP/AVP %d", port, int(payload)),
		fmt.Sprintf("a=rtpmap:%d %s/%d", int(payload), payload.Name(), rtp.ClockRate),
		"a=ptime:20",
		"a=sendrecv",
		"",
	}
	return []byte(strings.Join(lines, "\r\n"))
}
