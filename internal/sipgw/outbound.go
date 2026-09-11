// Outbound calls: a softphone dials, the gateway places the call on vocat.
//
// The gateway is the UAS here. The sequence is deliberately ordered so the phone
// never hears ringback for a call vocat refused: SDP is validated and the RTP
// socket opened first, then vocat is asked to dial, and only then is 180 sent.
package sipgw

import (
	"context"
	"net"
	"strings"
	"time"

	"vocat-plugin-telephony/internal/sip"
)

func (gateway *Gateway) handleInvite(message *sip.Message, source *net.UDPAddr) {
	callID := message.CallID()
	if callID == "" {
		gateway.respond(message, source, 400, nil, nil)
		return
	}

	// A re-INVITE inside a known dialog is a media change or a hold. The gateway
	// keeps the existing stream and simply re-answers, because tearing down the
	// bridge would drop audio on every hold/unhold cycle.
	if existing := gateway.dialogs.bySIPCallID(callID); existing != nil {
		gateway.handleReinvite(existing, message, source)
		return
	}

	if !gateway.authorize(message, source) {
		return
	}
	if gateway.dialogs.count() >= maxConcurrentCalls {
		// Each call holds an RTP socket, a WebSocket and two goroutines; refusing
		// is better than degrading every call in progress.
		gateway.respond(message, source, 486, nil, nil)
		return
	}

	number := dialogNumber(message.URI)
	if number == "" {
		if to, err := sip.ParseURI(message.Get("To")); err == nil {
			number = normalizeDialled(to.User)
		}
	}
	if !validDialNumber(number) {
		gateway.respond(message, source, 484, nil, nil)
		return
	}
	if strings.TrimSpace(message.Get("Content-Type")) != "" &&
		!strings.Contains(strings.ToLower(message.Get("Content-Type")), "sdp") {
		gateway.respond(message, source, 415, nil, nil)
		return
	}

	media, err := parseSDP(message.Body)
	if err != nil {
		// 488 is the honest answer: the offer is well-formed SIP but proposes
		// media this gateway cannot carry.
		gateway.logger.Warn("rejecting INVITE with unusable SDP",
			"source", source.String(), "error", err)
		gateway.respond(message, source, 488, nil, nil)
		return
	}

	localTag, err := randomToken(8)
	if err != nil {
		gateway.respond(message, source, 500, nil, nil)
		return
	}
	rtpSession, err := gateway.startRTP(media)
	if err != nil {
		gateway.logger.Warn("could not open RTP for an outbound call", "error", err)
		gateway.respond(message, source, 500, nil, nil)
		return
	}

	dlg := &dialog{
		direction:     outbound,
		callID:        callID,
		localTag:      localTag,
		remoteTag:     sip.Tag(message.Get("From")),
		localURI:      message.Get("To"),
		remoteURI:     message.Get("From"),
		target:        source.String(),
		contact:       message.Get("Contact"),
		route:         message.All("Record-Route"),
		via:           message.All("Via"),
		inviteRequest: message,
		deviceID:      gateway.config.Account.DeviceID,
		peer:          number,
		rtpSession:    rtpSession,
		state:         stateRinging,
		startedAt:     time.Now(),
	}

	// 100 Trying stops the phone retransmitting while vocat is contacted; the
	// dial request can take a moment because vocat probes the modem.
	gateway.respond(message, source, 100, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	call, err := gateway.client.DialCall(ctx, dlg.deviceID, number, 0)
	cancel()
	if err != nil {
		rtpSession.Close()
		gateway.logger.Warn("vocat refused an outbound call",
			"number", number, "error", err)
		// 503 rather than 500: the request was fine, the downstream service
		// could not carry it, and a phone will present that as "unavailable".
		gateway.respond(message, source, 503, nil, nil)
		return
	}
	if call.ID == "" {
		// vocat accepted the dial but reported no call id, so there is nothing to
		// hang up and nothing to bridge. Fail the INVITE rather than leaving a
		// dialog that can never be torn down.
		rtpSession.Close()
		gateway.logger.Warn("vocat returned no call id for an outbound dial", "number", number)
		gateway.respond(message, source, 500, nil, nil)
		return
	}

	gateway.dialogs.linkVocat(dlg, dlg.deviceID, call.ID)
	gateway.dialogs.add(dlg)

	// 180 Ringing only now, once vocat has accepted the dial: ringback for a call
	// that was never placed is the most confusing failure a user can hit.
	gateway.respond(message, source, 180, map[string]string{
		"Contact": gateway.contactHeader(source.IP),
		"To":      withTag(message.Get("To"), localTag),
	}, nil)

	gateway.logger.Info("outbound call placed",
		"number", number, "sip_call_id", callID, "vocat_call_id", call.ID)
}

// handleReinvite answers a media renegotiation without disturbing the bridge.
func (gateway *Gateway) handleReinvite(dlg *dialog, message *sip.Message, source *net.UDPAddr) {
	if !dlg.answered() {
		// An INVITE arriving twice before the answer is a retransmission, not a
		// renegotiation. Re-sending the provisional response is the correct reply.
		gateway.respond(message, source, 180, map[string]string{
			"Contact": gateway.contactHeader(source.IP),
			"To":      withTag(dlg.localURI, dlg.localTag),
		}, nil)
		return
	}
	if len(message.Body) > 0 {
		media, err := parseSDP(message.Body)
		if err != nil {
			// Keep the call up and refuse only the change; dropping a live call
			// because a hold offer was odd would be worse.
			gateway.respond(message, source, 488, nil, nil)
			return
		}
		if err := dlg.rtpSession.SetRemote(media.Address, media.Port); err != nil {
			gateway.respond(message, source, 488, nil, nil)
			return
		}
	}
	local := gateway.localAddressFor(source.IP)
	answer := buildSDP(local, dlg.rtpSession.LocalPort(), dlg.rtpSession.Payload(), time.Now().Unix())
	gateway.respond(message, source, 200, map[string]string{
		"Contact": gateway.contactHeader(source.IP),
		"To":      withTag(dlg.localURI, dlg.localTag),
	}, answer)
}

// answerOutbound sends 200 OK with the gateway's SDP once vocat reports the far
// end picked up. Called from the poll loop, not from a SIP handler.
func (gateway *Gateway) answerOutbound(dlg *dialog) {
	if dlg.answered() || dlg.currentState() == stateTerminated {
		return
	}
	target, err := net.ResolveUDPAddr("udp", dlg.target)
	if err != nil {
		gateway.terminate(dlg, "phone address unresolvable")
		return
	}
	local := gateway.localAddressFor(target.IP)
	answer := buildSDP(local, dlg.rtpSession.LocalPort(), dlg.rtpSession.Payload(), time.Now().Unix())

	// The bridge is started before 200 OK so the first audio the phone sends
	// after answering has somewhere to go. Starting it after would clip the
	// opening word.
	if err := gateway.attachBridge(dlg); err != nil {
		gateway.logger.Warn("could not bridge audio for an outbound call",
			"vocat_call_id", dlg.vocatCallID, "error", err)
		gateway.terminate(dlg, "audio bridge failed")
		return
	}
	dlg.setState(stateAnswered)
	gateway.respond(dlg.inviteRequest, target, 200, map[string]string{
		"Contact": gateway.contactHeader(target.IP),
		"To":      withTag(dlg.localURI, dlg.localTag),
	}, answer)
	gateway.logger.Info("outbound call answered",
		"sip_call_id", dlg.callID, "vocat_call_id", dlg.vocatCallID)
}

// attachBridge connects the RTP session to vocat's audio socket.
func (gateway *Gateway) attachBridge(dlg *dialog) error {
	if dlg.bridge != nil {
		return nil
	}
	// The bridge outlives any request context, so it gets its own, cancelled
	// only by dialog.close.
	ctx, cancel := context.WithCancel(context.Background())
	dlg.cancelBridge = cancel
	relay, err := startBridge(ctx, dlg.rtpSession,
		gateway.client.MediaURL(dlg.deviceID, dlg.vocatCallID), gateway.client.HTTPClient())
	if err != nil {
		cancel()
		dlg.cancelBridge = nil
		return err
	}
	dlg.bridge = relay
	return nil
}

func (gateway *Gateway) handleAck(message *sip.Message) {
	// ACK completes the three-way handshake and needs no response. It is tracked
	// only so a missing ACK can be told apart from a lost 200 in the logs.
	if dlg := gateway.dialogs.bySIPCallID(message.CallID()); dlg != nil {
		gateway.logger.Debug("ACK received", "sip_call_id", dlg.callID)
	}
}

func (gateway *Gateway) handleBye(message *sip.Message, source *net.UDPAddr) {
	dlg := gateway.dialogs.bySIPCallID(message.CallID())
	if dlg == nil {
		// 481 is required for an unknown dialog; answering 200 would leave the
		// client believing a call it does not have was just ended.
		gateway.respond(message, source, 481, nil, nil)
		return
	}
	// Answer before tearing down: the phone is waiting, and hanging up on vocat
	// can take a moment.
	gateway.respond(message, source, 200, nil, nil)
	gateway.terminate(dlg, "phone sent BYE")
}

func (gateway *Gateway) handleCancel(message *sip.Message, source *net.UDPAddr) {
	dlg := gateway.dialogs.bySIPCallID(message.CallID())
	// A CANCEL is always answered 200, then the pending INVITE is answered 487.
	gateway.respond(message, source, 200, nil, nil)
	if dlg == nil {
		return
	}
	if dlg.inviteRequest != nil && !dlg.answered() {
		gateway.respond(dlg.inviteRequest, source, 487, nil, nil)
	}
	gateway.terminate(dlg, "phone cancelled")
}

// withTag appends a tag parameter to a From/To header value, replacing any
// existing one so a retransmission cannot produce two tags.
func withTag(header, tag string) string {
	header = strings.TrimSpace(header)
	if tag == "" {
		return header
	}
	if existing := sip.Tag(header); existing != "" {
		return strings.Replace(header, ";tag="+existing, ";tag="+tag, 1)
	}
	return header + ";tag=" + tag
}

// validDialNumber mirrors vocat's own rule so the gateway refuses locally with
// 484 rather than round-tripping a rejection: digits, a leading +, * and #,
// length 2 to 32.
func validDialNumber(value string) bool {
	if len(value) < 2 || len(value) > 32 {
		return false
	}
	for index, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character == '+' && index == 0:
		case character == '*' || character == '#':
		default:
			return false
		}
	}
	return true
}
