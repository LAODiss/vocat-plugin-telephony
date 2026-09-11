// Dialog tracking for the B2BUA.
//
// Each active call has one dialog toward the softphone and one call on vocat's
// side. This file owns the pairing and the invariant that matters most: a
// terminated call must never leave an RTP socket, an audio bridge, or a vocat
// call behind. Every teardown path funnels through dialog.close.
package sipgw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/rtp"
	"vocat-plugin-telephony/internal/sip"
)

// direction distinguishes who started the call, because the SIP roles are
// mirrored: for an outbound call the gateway is the UAS, for inbound the UAC.
type direction int

const (
	outbound direction = iota // phone dialled out
	inbound                   // vocat received a call, gateway rings the phone
)

// dialogState is the SIP-side lifecycle.
type dialogState int

const (
	stateInviting dialogState = iota // inbound: INVITE sent, awaiting an answer
	stateRinging                     // outbound: 180 sent, awaiting answer
	stateAnswered
	stateTerminated
)

// dialog is one call bridged between a softphone and vocat.
type dialog struct {
	direction direction

	// SIP identity toward the phone.
	callID   string
	localTag string
	// remoteTag is learned from the phone's To tag on an inbound call, and from
	// its From tag on an outbound one.
	remoteTag string
	localURI  string
	remoteURI string
	// target is where requests and responses go: the observed source address,
	// never the Contact host.
	target string
	// contact is the phone's Contact URI, used as the request URI for in-dialog
	// requests such as BYE.
	contact string
	// route is the recorded route set, preserved in order.
	route []string
	// via holds the phone's Via stack for responses to its requests.
	via  []string
	cseq int
	// inviteRequest is kept so a CANCEL can be answered with a 487 on the
	// original transaction, and so an inbound INVITE can be retransmitted.
	inviteRequest *sip.Message

	// vocat side.
	deviceID    string
	vocatCallID string
	// peer is the number as dialled or as presented by the caller.
	peer string

	rtpSession *rtp.Session
	bridge     *bridge

	mu         sync.Mutex
	state      dialogState
	startedAt  time.Time
	answeredAt time.Time
	closeOnce  sync.Once
	// cancelBridge stops the bridge's goroutines independently of the caller's
	// request context, which is long gone by the time a call ends.
	cancelBridge context.CancelFunc
}

func (dlg *dialog) setState(state dialogState) {
	dlg.mu.Lock()
	defer dlg.mu.Unlock()
	dlg.state = state
	if state == stateAnswered && dlg.answeredAt.IsZero() {
		dlg.answeredAt = time.Now()
	}
}

func (dlg *dialog) currentState() dialogState {
	dlg.mu.Lock()
	defer dlg.mu.Unlock()
	return dlg.state
}

func (dlg *dialog) answered() bool {
	return dlg.currentState() == stateAnswered
}

// close releases everything this dialog owns. It is idempotent because a call
// can end from either side at the same moment: the phone sends BYE while vocat
// reports the call gone, and both paths call this.
func (dlg *dialog) close() {
	dlg.closeOnce.Do(func() {
		dlg.setState(stateTerminated)
		if dlg.cancelBridge != nil {
			dlg.cancelBridge()
		}
		// The bridge owns both sockets once started, so closing it is what
		// releases the RTP session too. Before that, the session stands alone.
		if dlg.bridge != nil {
			dlg.bridge.Close()
		} else if dlg.rtpSession != nil {
			dlg.rtpSession.Close()
		}
	})
}

// key identifies a dialog by its SIP Call-ID. One softphone dialog maps to one
// vocat call, so this is sufficient without the full local/remote tag triple.
func (dlg *dialog) key() string {
	return dlg.callID
}

// dialogTable indexes active dialogs by both identities, because lookups arrive
// from both sides: SIP messages carry a Call-ID, vocat polling carries its own
// call id.
type dialogTable struct {
	mu      sync.RWMutex
	bySIP   map[string]*dialog
	byVocat map[string]*dialog
}

func newDialogTable() *dialogTable {
	return &dialogTable{
		bySIP:   map[string]*dialog{},
		byVocat: map[string]*dialog{},
	}
}

func (table *dialogTable) add(dlg *dialog) {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.bySIP[dlg.callID] = dlg
	if dlg.vocatCallID != "" {
		table.byVocat[vocatKey(dlg.deviceID, dlg.vocatCallID)] = dlg
	}
}

// addSIPOnly indexes a dialog by its SIP Call-ID alone. A forked inbound call
// has several dialogs sharing one vocat call, so indexing them all by the vocat
// id would collide; the winner is linked once it answers.
func (table *dialogTable) addSIPOnly(dlg *dialog) {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.bySIP[dlg.callID] = dlg
}

// linkVocat records the vocat call id once it is known. An outbound call learns
// it only after the dial request returns.
func (table *dialogTable) linkVocat(dlg *dialog, deviceID, vocatCallID string) {
	table.mu.Lock()
	defer table.mu.Unlock()
	dlg.deviceID = deviceID
	dlg.vocatCallID = vocatCallID
	if vocatCallID != "" {
		table.byVocat[vocatKey(deviceID, vocatCallID)] = dlg
	}
}

func (table *dialogTable) bySIPCallID(callID string) *dialog {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return table.bySIP[callID]
}

func (table *dialogTable) byVocatCall(deviceID, callID string) *dialog {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return table.byVocat[vocatKey(deviceID, callID)]
}

func (table *dialogTable) remove(dlg *dialog) {
	table.mu.Lock()
	defer table.mu.Unlock()
	delete(table.bySIP, dlg.callID)
	if dlg.vocatCallID != "" {
		delete(table.byVocat, vocatKey(dlg.deviceID, dlg.vocatCallID))
	}
}

func (table *dialogTable) all() []*dialog {
	table.mu.RLock()
	defer table.mu.RUnlock()
	dialogs := make([]*dialog, 0, len(table.bySIP))
	for _, dlg := range table.bySIP {
		dialogs = append(dialogs, dlg)
	}
	return dialogs
}

func (table *dialogTable) count() int {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return len(table.bySIP)
}

func vocatKey(deviceID, callID string) string {
	return deviceID + "|" + callID
}

// randomToken produces tags, branches and Call-IDs. These must be
// unguessable: a predictable branch or tag lets an off-path attacker inject a
// response into a transaction.
func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("sipgw: generate token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// branchToken produces an RFC 3261 magic-cookie branch parameter.
func branchToken() (string, error) {
	token, err := randomToken(8)
	if err != nil {
		return "", err
	}
	return "z9hG4bK" + token, nil
}

// firstVia returns the topmost Via, which is where a response must go.
func firstVia(message *sip.Message) string {
	values := message.All("Via")
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// dialogNumber extracts the dialled number from a request URI. A softphone may
// present it as sip:, sips: or tel:, with or without a host.
func dialogNumber(requestURI string) string {
	uri, err := sip.ParseURI(requestURI)
	if err != nil {
		return ""
	}
	if uri.Scheme == "tel" {
		return normalizeDialled(uri.Host)
	}
	if uri.User != "" {
		return normalizeDialled(uri.User)
	}
	// A bare host is only a number when it looks like one, which is how some
	// clients encode a short code.
	return normalizeDialled(uri.Host)
}

// normalizeDialled keeps only the characters vocat accepts in a dial string,
// preserving a leading + because it distinguishes an international number.
func normalizeDialled(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for index, character := range value {
		switch {
		case character >= '0' && character <= '9':
			builder.WriteRune(character)
		case character == '+' && index == 0:
			builder.WriteRune(character)
		case character == '*' || character == '#':
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
