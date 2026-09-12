// Inbound calls: vocat receives a call, the gateway rings the registered
// softphones.
//
// The gateway is the UAC here. vocat offers no event channel a plugin can
// subscribe to, so the only way to notice a ringing call — or that a call was
// answered or ended — is to poll. That is the honest limitation of this design:
// a call that starts and ends inside one poll interval is never seen.
//
// When several devices are registered, all of them are invited at once and the
// first to answer wins; the others are cancelled. Serial ringing would leave the
// caller listening to silence while each device is tried in turn.
package sipgw

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"vocat-plugin-telephony/internal/rtp"
	"vocat-plugin-telephony/internal/sip"
	"vocat-plugin-telephony/internal/vocat"
)

// pollVocat watches vocat for call state and drives both directions.
func (gateway *Gateway) pollVocat() {
	defer gateway.wg.Done()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-gateway.done:
			return
		case <-ticker.C:
			gateway.reconcile()
		}
	}
}

func (gateway *Gateway) reconcile() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	deviceID := gateway.config.Account.DeviceID
	snapshot, err := gateway.client.Calls(ctx, deviceID)
	if err != nil {
		gateway.mu.Lock()
		gateway.lastErr = err.Error()
		gateway.mu.Unlock()
		return
	}
	gateway.mu.Lock()
	gateway.lastErr = ""
	gateway.mu.Unlock()

	// Only the VoWiFi transport reports a stable call id and state machine. The
	// cellular transport returns AT-derived integers with no id, which cannot be
	// mapped to a SIP dialog.
	if snapshot.Transport != "vowifi" {
		return
	}

	live := map[string]vocat.Call{}
	for _, call := range snapshot.Calls {
		if call.Live() {
			live[call.ID] = call
		}
		gateway.advanceCall(deviceID, call)
	}

	// A dialog whose vocat call vanished must be torn down: vocat discards a
	// terminated call from its list shortly after it ends, so absence is the
	// normal end-of-call signal rather than an error.
	for _, dlg := range gateway.dialogs.all() {
		if dlg.vocatCallID == "" {
			continue
		}
		if _, present := live[dlg.vocatCallID]; !present {
			gateway.terminate(dlg, "vocat call ended")
		}
	}
}

// advanceCall reacts to one call's current state.
func (gateway *Gateway) advanceCall(deviceID string, call vocat.Call) {
	dlg := gateway.dialogs.byVocatCall(deviceID, call.ID)

	if dlg == nil {
		// An inbound call vocat is ringing, with no dialog yet: offer it to the
		// registered phones.
		if call.Ringing() {
			gateway.offerToPhones(deviceID, call)
		}
		return
	}

	switch {
	case !call.Live():
		gateway.terminate(dlg, "vocat reported the call finished")
	case dlg.direction == outbound && call.State == "active" && !dlg.answered():
		// The far end picked up. Answer the phone's INVITE now.
		gateway.answerOutbound(dlg)
	case dlg.direction == inbound && dlg.answered() && dlg.bridge == nil && call.MediaReady:
		// Media became ready after the phone answered; attach the bridge as soon
		// as it does, or the first seconds of the call are silent.
		if err := gateway.attachBridge(dlg); err != nil {
			gateway.logger.Warn("could not bridge audio for an inbound call",
				"vocat_call_id", call.ID, "error", err)
			gateway.terminate(dlg, "audio bridge failed")
		}
	}
}

// offerToPhones sends an INVITE to every registered client for a ringing vocat
// call. The first to answer wins.
func (gateway *Gateway) offerToPhones(deviceID string, call vocat.Call) {
	targets := gateway.registrar.Targets()
	if len(targets) == 0 {
		// Nothing is registered. The call is left alone rather than rejected: the
		// operator may still answer it in vocat's own web UI, and the plugin's
		// rule engine may have its own plan for it.
		return
	}
	if gateway.dialogs.count() >= maxConcurrentCalls {
		return
	}
	// A guard against inviting the same call twice: the poll runs every second
	// and an INVITE takes longer than that to be answered.
	gateway.inboundMu.Lock()
	if _, pending := gateway.inboundPending[call.ID]; pending {
		gateway.inboundMu.Unlock()
		return
	}
	if gateway.inboundPending == nil {
		gateway.inboundPending = map[string]struct{}{}
	}
	gateway.inboundPending[call.ID] = struct{}{}
	gateway.inboundMu.Unlock()

	gateway.wg.Add(1)
	go func() {
		defer gateway.wg.Done()
		defer func() {
			gateway.inboundMu.Lock()
			delete(gateway.inboundPending, call.ID)
			gateway.inboundMu.Unlock()
		}()
		gateway.forkInbound(deviceID, call, targets)
	}()
}

// forkInbound invites every registered client and settles on the first answer.
func (gateway *Gateway) forkInbound(deviceID string, call vocat.Call, targets []Binding) {
	branches := make([]*inboundBranch, 0, len(targets))
	for _, binding := range targets {
		branch, err := gateway.inviteBranch(deviceID, call, binding)
		if err != nil {
			gateway.logger.Warn("could not invite a registered client",
				"target", binding.Target, "error", err)
			continue
		}
		branches = append(branches, branch)
	}
	if len(branches) == 0 {
		return
	}

	deadline := time.NewTimer(inviteTimeout)
	defer deadline.Stop()

	for {
		select {
		case <-gateway.done:
			gateway.abandonBranches(branches, nil)
			return
		case <-deadline.C:
			// Nobody answered. Cancel every branch and let vocat's own timeout or
			// the caller end the call; the gateway does not reject it, because the
			// operator may still pick up elsewhere.
			gateway.abandonBranches(branches, nil)
			return
		case winner := <-gateway.answers:
			if winner.callID == "" {
				continue
			}
			// Only settle branches belonging to this fork.
			if !branchBelongs(branches, winner.callID) {
				// Another fork's answer; put it back for its own waiter.
				go func(answer inboundAnswer) { gateway.answers <- answer }(winner)
				continue
			}
			gateway.settleInbound(deviceID, call, branches, winner)
			return
		}
	}
}

// inboundBranch is one outstanding INVITE toward a registered client.
type inboundBranch struct {
	binding Binding
	dlg     *dialog
}

// inboundAnswer is delivered when a client answers a forked INVITE.
type inboundAnswer struct {
	callID string
}

func branchBelongs(branches []*inboundBranch, callID string) bool {
	for _, branch := range branches {
		if branch.dlg.callID == callID {
			return true
		}
	}
	return false
}

// inviteBranch sends one INVITE and registers the pending dialog.
func (gateway *Gateway) inviteBranch(deviceID string, call vocat.Call, binding Binding) (*inboundBranch, error) {
	target, err := net.ResolveUDPAddr("udp", binding.Target)
	if err != nil {
		return nil, err
	}
	callID, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	localTag, err := randomToken(8)
	if err != nil {
		return nil, err
	}
	branch, err := branchToken()
	if err != nil {
		return nil, err
	}

	// The RTP socket is opened before the INVITE because its port has to appear
	// in the offer. The remote end is unknown until the answer arrives.
	rtpSession, err := gateway.openInboundRTP()
	if err != nil {
		return nil, err
	}

	local := gateway.localAddressFor(target.IP)
	contact := gateway.contactHeader(target.IP)
	caller := strings.TrimSpace(call.Number)
	if caller == "" {
		caller = "anonymous"
	}
	fromURI := "<sip:" + caller + "@" + gateway.auth.Realm() + ">"
	toURI := "<sip:" + gateway.config.Account.Username + "@" + gateway.auth.Realm() + ">"

	invite := &sip.Message{Method: "INVITE", URI: uriFromContact(binding.Contact, binding.Target)}
	invite.Add("Via", "SIP/2.0/UDP "+
		net.JoinHostPort(local.String(), strconv.Itoa(gateway.localPort()))+
		";branch="+branch+";rport")
	invite.Add("Max-Forwards", "70")
	invite.Add("From", fromURI+";tag="+localTag)
	invite.Add("To", toURI)
	invite.Add("Call-ID", callID)
	invite.Add("CSeq", "1 INVITE")
	invite.Add("Contact", contact)
	invite.Add("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS")
	invite.Add("User-Agent", "vocat-telephony-gateway/1")
	invite.Add("Content-Type", "application/sdp")
	invite.Body = buildSDP(local, rtpSession.LocalPort(), rtpSession.Payload(), time.Now().Unix())

	dlg := &dialog{
		direction:     inbound,
		callID:        callID,
		localTag:      localTag,
		localURI:      fromURI,
		remoteURI:     toURI,
		target:        binding.Target,
		contact:       binding.Contact,
		cseq:          1,
		inviteRequest: invite,
		deviceID:      deviceID,
		vocatCallID:   call.ID,
		peer:          caller,
		rtpSession:    rtpSession,
		state:         stateInviting,
		startedAt:     time.Now(),
	}
	// Indexed by SIP Call-ID only: several branches share one vocat call, so the
	// vocat index would collide. The winner is linked after it answers.
	gateway.dialogs.addSIPOnly(dlg)

	gateway.send(invite, target)
	gateway.logger.Info("ringing a registered client",
		"target", binding.Target, "caller", caller, "vocat_call_id", call.ID)
	return &inboundBranch{binding: binding, dlg: dlg}, nil
}

// openInboundRTP opens a media socket for an offer whose answer has not arrived.
// PCMA is offered because it is the more common default in the clients this
// gateway targets; the answer's SDP then fixes the remote end.
func (gateway *Gateway) openInboundRTP() (*rtp.Session, error) {
	return rtp.Listen(rtp.Options{
		ListenIP: gateway.rtpListenIP(),
		Payload:  rtp.PayloadPCMA,
	})
}

// settleInbound accepts the winning branch and cancels the rest.
func (gateway *Gateway) settleInbound(
	deviceID string,
	call vocat.Call,
	branches []*inboundBranch,
	winner inboundAnswer,
) {
	var chosen *dialog
	var losers []*dialog
	for _, branch := range branches {
		if branch.dlg.callID == winner.callID {
			chosen = branch.dlg
			continue
		}
		losers = append(losers, branch.dlg)
	}
	if chosen == nil {
		return
	}

	// Answer vocat first. If this fails the phone must not be left in a call that
	// has no far end.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, err := gateway.client.AnswerCall(ctx, deviceID, call.ID)
	cancel()
	if err != nil {
		gateway.logger.Warn("vocat refused to answer an inbound call",
			"vocat_call_id", call.ID, "error", err)
		gateway.byeDialog(chosen, "vocat could not answer")
		gateway.abandonBranches(branches, nil)
		return
	}

	gateway.dialogs.linkVocat(chosen, deviceID, call.ID)
	chosen.setState(stateAnswered)
	// The bridge attaches on the next poll once vocat reports media ready; doing
	// it here would usually be too early.
	gateway.abandonBranches(branches, chosen)
	gateway.logger.Info("inbound call answered by a client",
		"target", chosen.target, "vocat_call_id", call.ID)
}

// abandonBranches cancels every branch except the winner.
func (gateway *Gateway) abandonBranches(branches []*inboundBranch, winner *dialog) {
	for _, branch := range branches {
		if winner != nil && branch.dlg == winner {
			continue
		}
		gateway.cancelBranch(branch.dlg)
	}
}

// cancelBranch withdraws an outstanding INVITE from a client that did not win.
func (gateway *Gateway) cancelBranch(dlg *dialog) {
	if dlg.currentState() == stateTerminated {
		return
	}
	target, err := net.ResolveUDPAddr("udp", dlg.target)
	if err == nil && dlg.inviteRequest != nil {
		// The resolved endpoint must be a SIP port; sending a CANCEL to a
		// non-SIP port would be silently lost and leave the branch dangling.
		if target.Port == 0 || target.Port == 65535 {
			gateway.logger.Warn("cancelBranch: invalid target port", "target", dlg.target)
			dlg.close()
			gateway.dialogs.remove(dlg)
			return
		}
		cancel := &sip.Message{Method: "CANCEL", URI: dlg.inviteRequest.URI}
		// A CANCEL must carry the same branch as the INVITE it withdraws, or the
		// client will not match it to the pending transaction.
		for _, via := range dlg.inviteRequest.All("Via") {
			cancel.Add("Via", via)
		}
		cancel.Add("Max-Forwards", "70")
		cancel.Add("From", dlg.inviteRequest.Get("From"))
		cancel.Add("To", dlg.inviteRequest.Get("To"))
		cancel.Add("Call-ID", dlg.callID)
		cancel.Add("CSeq", strconv.Itoa(dlg.cseq)+" CANCEL")
		gateway.send(cancel, target)
	}
	dlg.close()
	gateway.dialogs.remove(dlg)
}

// byeDialog ends an answered dialog toward the phone without touching vocat,
// used when vocat itself is the thing that failed.
func (gateway *Gateway) byeDialog(dlg *dialog, reason string) {
	target, err := net.ResolveUDPAddr("udp", dlg.target)
	if err == nil {
		dlg.cseq++
		bye := &sip.Message{Method: "BYE", URI: uriFromContact(dlg.contact, dlg.target)}
		branch, tokenErr := branchToken()
		if tokenErr == nil {
			local := gateway.localAddressFor(target.IP)
			bye.Add("Via", "SIP/2.0/UDP "+
				net.JoinHostPort(local.String(), strconv.Itoa(gateway.localPort()))+
				";branch="+branch+";rport")
		}
		bye.Add("Max-Forwards", "70")
		bye.Add("From", withTag(dlg.localURI, dlg.localTag))
		bye.Add("To", withTag(dlg.remoteURI, dlg.remoteTag))
		bye.Add("Call-ID", dlg.callID)
		bye.Add("CSeq", strconv.Itoa(dlg.cseq)+" BYE")
		gateway.send(bye, target)
	}
	dlg.close()
	gateway.dialogs.remove(dlg)
	gateway.logger.Info("ended a dialog toward the phone",
		"sip_call_id", dlg.callID, "reason", reason)
}

// handleResponse processes responses to the gateway's own requests, which are
// the forked INVITEs toward registered clients.
func (gateway *Gateway) handleResponse(message *sip.Message, source *net.UDPAddr) {
	_, method := message.CSeq()
	if method != "INVITE" {
		// Responses to BYE and CANCEL need no action; the dialog is already gone.
		return
	}
	dlg := gateway.dialogs.bySIPCallID(message.CallID())
	if dlg == nil || dlg.direction != inbound {
		return
	}

	switch {
	case message.StatusCode < 200:
		// Provisional: the client is alerting. Nothing to do but note it.
		if message.StatusCode >= 180 {
			dlg.setState(stateRinging)
		}
	case message.StatusCode < 300:
		gateway.acceptInboundAnswer(dlg, message, source)
	default:
		// The client declined or failed. Its branch is done; the fork waiter
		// decides what happens to the call overall.
		gateway.logger.Info("a client declined an inbound call",
			"target", dlg.target, "status", message.StatusCode)
		dlg.close()
		gateway.dialogs.remove(dlg)
	}
}

// acceptInboundAnswer completes the handshake with the client that answered.
func (gateway *Gateway) acceptInboundAnswer(dlg *dialog, message *sip.Message, source *net.UDPAddr) {
	if dlg.currentState() == stateAnswered {
		// A retransmitted 200; the ACK must be repeated but nothing else changes.
		gateway.sendAck(dlg, message, source)
		return
	}
	if len(message.Body) > 0 {
		media, err := parseSDP(message.Body)
		if err != nil {
			gateway.logger.Warn("client answered with unusable SDP",
				"target", dlg.target, "error", err)
			gateway.sendAck(dlg, message, source)
			gateway.byeDialog(dlg, "unusable answer SDP")
			return
		}
		if err := dlg.rtpSession.SetRemote(media.Address, media.Port); err != nil {
			gateway.sendAck(dlg, message, source)
			gateway.byeDialog(dlg, "unusable answer address")
			return
		}
	}
	dlg.remoteTag = sip.Tag(message.Get("To"))
	if contact := message.Get("Contact"); contact != "" {
		dlg.contact = contact
	}
	// ACK first: the client is waiting for it and will retransmit 200 until it
	// arrives.
	gateway.sendAck(dlg, message, source)

	// Hand the win to the fork waiter, which answers vocat and cancels the rest.
	select {
	case gateway.answers <- inboundAnswer{callID: dlg.callID}:
	default:
		// No waiter is listening, which means the fork already settled or timed
		// out. Ending this dialog is the only correct outcome.
		gateway.byeDialog(dlg, "fork already settled")
	}
}

func (gateway *Gateway) sendAck(dlg *dialog, response *sip.Message, source *net.UDPAddr) {
	target := source
	if dlg.target != "" {
		if resolved, err := net.ResolveUDPAddr("udp", dlg.target); err == nil {
			target = resolved
		}
	}
	branch, err := branchToken()
	if err != nil {
		return
	}
	local := gateway.localAddressFor(target.IP)
	ack := &sip.Message{Method: "ACK", URI: uriFromContact(dlg.contact, dlg.target)}
	ack.Add("Via", "SIP/2.0/UDP "+
		net.JoinHostPort(local.String(), strconv.Itoa(gateway.localPort()))+
		";branch="+branch+";rport")
	ack.Add("Max-Forwards", "70")
	ack.Add("From", response.Get("From"))
	ack.Add("To", response.Get("To"))
	ack.Add("Call-ID", dlg.callID)
	// An ACK reuses the INVITE's sequence number, unlike every other request.
	ack.Add("CSeq", strconv.Itoa(dlg.cseq)+" ACK")
	gateway.send(ack, target)
}

// uriFromContact picks the request URI for an in-dialog request. The Contact URI
// is correct per RFC 3261, but a NAT-bound client's Contact host is unreachable,
// so the observed target's host is substituted while the user part is kept.
func uriFromContact(contact, target string) string {
	uri, err := sip.ParseURI(contact)
	if err != nil {
		return "sip:" + target
	}
	host, port, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		return uri.String()
	}
	portNumber, convErr := strconv.Atoi(port)
	if convErr != nil {
		return uri.String()
	}
	uri.Host = host
	uri.Port = portNumber
	return uri.String()
}
