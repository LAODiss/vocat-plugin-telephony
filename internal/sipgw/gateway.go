// Package sipgw is a SIP gateway that lets a softphone place and receive calls
// through vocat.
//
// It is a back-to-back user agent: one dialog toward the phone, one call on
// vocat's HTTP API, and an audio relay between the phone's RTP stream and
// vocat's PCM WebSocket. Both sides are 8 kHz mono, so no resampling happens
// anywhere in the path.
//
// Three things about this design deserve to be stated plainly rather than
// discovered later.
//
// The SIP port is not behind vocat's access control. vocat only reverse-proxies
// HTTP to the plugin; this package binds its own UDP socket. Everything guarding
// it lives here: mandatory digest authentication, a bind address that defaults
// to the local network, an optional source allowlist, and the authenticator's
// failure lockout. A SIP port exposed to the internet is scanned within hours,
// and a successful guess places calls on the operator's SIM.
//
// It requires vocat credentials. A softphone dials when no browser is open, so
// the gateway must be able to call vocat's API itself. That is the plugin's
// server-side mode, and without it this package cannot run.
//
// It cannot send DTMF. vocat has no DTMF path at all, so the SDP deliberately
// omits telephone-event and clients fall back to in-band tones.
package sipgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/rtp"
	"vocat-plugin-telephony/internal/sip"
	"vocat-plugin-telephony/internal/vocat"
)

const (
	// readBufferBytes bounds one datagram. Anything larger is refused by the
	// parser rather than truncated into something that parses but means
	// something else.
	readBufferBytes = sip.MaxMessageBytes
	// inviteTimeout gives the far end time to answer before the gateway gives
	// up on an inbound call it is offering to the phone.
	inviteTimeout = 60 * time.Second
	// pollInterval is how often vocat is polled for call state. vocat offers no
	// event channel a plugin can subscribe to, so this is the only way to notice
	// that a call was answered or ended.
	pollInterval = time.Second
	// maxConcurrentCalls bounds resource use on a small appliance; each call
	// holds an RTP socket, a WebSocket and two goroutines.
	maxConcurrentCalls = 4
)

// Account is the single SIP account this gateway serves.
type Account struct {
	Username string
	Password string
	// DeviceID is the vocat device whose SIM carries the calls.
	DeviceID string
}

// Config configures the gateway.
type Config struct {
	// ListenAddress is the UDP address to bind, host:port. An empty host binds
	// every interface, which is deliberately not the default the panel offers.
	ListenAddress string
	// AdvertiseIP is the address put in SDP and Contact headers. When empty it is
	// derived per client from the local end of the socket, which is what makes a
	// multi-homed host work.
	AdvertiseIP string
	Realm       string
	Account     Account
	// AllowedSources restricts which CIDRs may register. Empty allows any source
	// that authenticates, which is only reasonable on a trusted network.
	AllowedSources []string
}

// Gateway is the running SIP service.
type Gateway struct {
	config    Config
	client    *vocat.Client
	logger    *slog.Logger
	auth      *sip.Authenticator
	registrar *Registrar
	dialogs   *dialogTable

	conn    *net.UDPConn
	allowed []*net.IPNet
	// advertise is the parsed AdvertiseIP, or nil to derive it per packet.
	advertise net.IP

	mu      sync.RWMutex
	running bool
	lastErr string

	// inboundPending guards against inviting the same vocat call twice: the poll
	// runs every second and an INVITE takes longer than that to be answered.
	inboundMu      sync.Mutex
	inboundPending map[string]struct{}
	// answers carries a forked INVITE's winner to the goroutine waiting on it.
	answers chan inboundAnswer

	stopOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

// New validates the configuration and prepares a gateway. It does not bind yet.
func New(config Config, client *vocat.Client, logger *slog.Logger) (*Gateway, error) {
	if client == nil {
		// Without vocat credentials the gateway could accept a call and then be
		// unable to place it, which is worse than refusing to start.
		return nil, errors.New("sipgw: vocat credentials are required; enable server-side mode first")
	}
	if strings.TrimSpace(config.Account.Username) == "" || config.Account.Password == "" {
		return nil, errors.New("sipgw: a SIP username and password are required")
	}
	if strings.TrimSpace(config.Account.DeviceID) == "" {
		return nil, errors.New("sipgw: a vocat device must be selected")
	}
	if logger == nil {
		logger = slog.Default()
	}
	realm := strings.TrimSpace(config.Realm)
	if realm == "" {
		realm = "vocat"
	}
	auth, err := sip.NewAuthenticator(realm)
	if err != nil {
		return nil, err
	}
	allowed, err := parseCIDRs(config.AllowedSources)
	if err != nil {
		return nil, err
	}
	var advertise net.IP
	if raw := strings.TrimSpace(config.AdvertiseIP); raw != "" {
		if advertise = net.ParseIP(raw); advertise == nil {
			return nil, fmt.Errorf("sipgw: advertise address %q is not an IP", raw)
		}
	}
	return &Gateway{
		config:         config,
		client:         client,
		logger:         logger,
		auth:           auth,
		registrar:      NewRegistrar(),
		dialogs:        newDialogTable(),
		allowed:        allowed,
		advertise:      advertise,
		inboundPending: map[string]struct{}{},
		// Buffered so a client answering at the moment a fork times out does not
		// block the SIP read loop.
		answers: make(chan inboundAnswer, maxConcurrentCalls),
		done:    make(chan struct{}),
	}, nil
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// A bare address is accepted as a single-host rule, which is what an
		// operator naturally types.
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				raw = fmt.Sprintf("%s/%d", ip.String(), bits)
			}
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("sipgw: allowed source %q is not a CIDR: %w", raw, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// Start binds the socket and begins serving. It returns once listening, with
// the serving loops running in the background.
func (gateway *Gateway) Start() error {
	address := strings.TrimSpace(gateway.config.ListenAddress)
	if address == "" {
		address = "0.0.0.0:5060"
	}
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("sipgw: resolve %q: %w", address, err)
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("sipgw: bind %s: %w", address, err)
	}
	gateway.conn = conn
	gateway.mu.Lock()
	gateway.running = true
	gateway.lastErr = ""
	gateway.mu.Unlock()

	gateway.wg.Add(2)
	go gateway.serve()
	go gateway.pollVocat()
	gateway.logger.Info("SIP gateway listening",
		"address", conn.LocalAddr().String(),
		"realm", gateway.auth.Realm(),
		"device_id", gateway.config.Account.DeviceID,
		"restricted", len(gateway.allowed) > 0)
	return nil
}

// Stop tears everything down: the socket, both loops, and every live call.
func (gateway *Gateway) Stop() {
	gateway.stopOnce.Do(func() {
		close(gateway.done)
		if gateway.conn != nil {
			// Closing the socket is what unblocks the read loop.
			_ = gateway.conn.Close()
		}
		for _, dlg := range gateway.dialogs.all() {
			gateway.terminate(dlg, "gateway stopping")
		}
		gateway.wg.Wait()
		gateway.registrar.Clear()
		gateway.mu.Lock()
		gateway.running = false
		gateway.mu.Unlock()
		gateway.logger.Info("SIP gateway stopped")
	})
}

// Status is what the panel shows.
type Status struct {
	Running     bool            `json:"running"`
	Address     string          `json:"address,omitempty"`
	Realm       string          `json:"realm,omitempty"`
	Error       string          `json:"error,omitempty"`
	Registered  bool            `json:"registered"`
	Bindings    []BindingStatus `json:"bindings"`
	ActiveCalls int             `json:"active_calls"`
	LockedPeers int             `json:"locked_peers"`
	Restricted  bool            `json:"restricted"`
}

// BindingStatus is one registered client, for display.
type BindingStatus struct {
	Contact   string `json:"contact"`
	Target    string `json:"target"`
	UserAgent string `json:"user_agent,omitempty"`
	ExpiresIn int    `json:"expires_in"`
	OnlineFor int    `json:"online_for"`
}

func (gateway *Gateway) Status() Status {
	gateway.mu.RLock()
	running, lastErr := gateway.running, gateway.lastErr
	gateway.mu.RUnlock()

	status := Status{
		Running:     running,
		Realm:       gateway.auth.Realm(),
		Error:       lastErr,
		ActiveCalls: gateway.dialogs.count(),
		LockedPeers: gateway.auth.LockedSources(),
		Restricted:  len(gateway.allowed) > 0,
	}
	if gateway.conn != nil && running {
		status.Address = gateway.conn.LocalAddr().String()
	}
	now := time.Now()
	for _, binding := range gateway.registrar.Targets() {
		status.Bindings = append(status.Bindings, BindingStatus{
			Contact:   binding.Contact,
			Target:    binding.Target,
			UserAgent: binding.UserAgent,
			ExpiresIn: int(binding.ExpiresAt.Sub(now).Seconds()),
			OnlineFor: int(now.Sub(binding.CreatedAt).Seconds()),
		})
	}
	status.Registered = len(status.Bindings) > 0
	if status.Bindings == nil {
		status.Bindings = []BindingStatus{}
	}
	return status
}

func (gateway *Gateway) serve() {
	defer gateway.wg.Done()
	buffer := make([]byte, readBufferBytes)
	for {
		count, source, err := gateway.conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-gateway.done:
				return
			default:
			}
			// A transient read error should not kill the gateway; record it and
			// keep serving.
			gateway.mu.Lock()
			gateway.lastErr = err.Error()
			gateway.mu.Unlock()
			return
		}
		packet := make([]byte, count)
		copy(packet, buffer[:count])
		gateway.handlePacket(packet, source)
	}
}

func (gateway *Gateway) handlePacket(packet []byte, source *net.UDPAddr) {
	if !gateway.sourceAllowed(source.IP) {
		// Silent drop, not a 403: answering tells a scanner the port is live.
		return
	}
	message, err := sip.Parse(packet)
	if err != nil {
		return
	}
	if message.IsResponse {
		gateway.handleResponse(message, source)
		return
	}
	switch message.Method {
	case "REGISTER":
		gateway.handleRegister(message, source)
	case "INVITE":
		gateway.handleInvite(message, source)
	case "ACK":
		gateway.handleAck(message)
	case "BYE":
		gateway.handleBye(message, source)
	case "CANCEL":
		gateway.handleCancel(message, source)
	case "OPTIONS":
		// Clients use OPTIONS as a keepalive; answering keeps them from tearing
		// down their registration.
		gateway.respond(message, source, 200, nil, nil)
	default:
		gateway.respond(message, source, 405, map[string]string{
			"Allow": "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS",
		}, nil)
	}
}

func (gateway *Gateway) sourceAllowed(ip net.IP) bool {
	if len(gateway.allowed) == 0 {
		return true
	}
	for _, network := range gateway.allowed {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// credentials is the account in the form the authenticator expects.
func (gateway *Gateway) credentials() sip.Credentials {
	return sip.Credentials{
		Username: gateway.config.Account.Username,
		Password: gateway.config.Account.Password,
		Realm:    gateway.auth.Realm(),
	}
}

// authorize verifies a request and answers the client when it cannot proceed.
// It returns true only when the request is authenticated.
func (gateway *Gateway) authorize(message *sip.Message, source *net.UDPAddr) bool {
	switch gateway.auth.Verify(message, gateway.credentials(), source.IP.String()) {
	case sip.ResultOK:
		return true
	case sip.ResultChallenge:
		gateway.respond(message, source, 401, map[string]string{
			"WWW-Authenticate": gateway.auth.ChallengeHeader(),
		}, nil)
	case sip.ResultReject:
		// A wrong password is answered with a fresh challenge rather than 403, so
		// a user who mistyped can retry without reconfiguring the client.
		gateway.respond(message, source, 401, map[string]string{
			"WWW-Authenticate": gateway.auth.ChallengeHeader(),
		}, nil)
		gateway.logger.Warn("SIP authentication failed",
			"source", source.String(), "method", message.Method)
	case sip.ResultLocked:
		gateway.respond(message, source, 403, nil, nil)
		gateway.logger.Warn("SIP source is locked out after repeated failures",
			"source", source.String())
	}
	return false
}

func (gateway *Gateway) handleRegister(message *sip.Message, source *net.UDPAddr) {
	if !gateway.authorize(message, source) {
		return
	}
	// The account name in the To header must match, or a valid password for one
	// account would register any address of record.
	if to, err := sip.ParseURI(message.Get("To")); err == nil {
		if !strings.EqualFold(to.User, gateway.config.Account.Username) {
			gateway.respond(message, source, 403, nil, nil)
			return
		}
	}

	if sip.IsUnregister(message) {
		gateway.registrar.Unregister(message)
		gateway.respond(message, source, 200, map[string]string{"Expires": "0"}, nil)
		gateway.logger.Info("SIP client unregistered", "source", source.String())
		return
	}
	requested, present := sip.Expires(message)
	granted := NormalizeExpiry(requested, present)
	binding := gateway.registrar.Register(message, source.String(), granted)
	gateway.respond(message, source, 200, map[string]string{
		"Contact": fmt.Sprintf("%s;expires=%d", binding.Contact, granted),
		"Expires": strconv.Itoa(granted),
	}, nil)
	gateway.logger.Info("SIP client registered",
		"source", source.String(), "user_agent", binding.UserAgent, "expires", granted)
}

// respond sends a response to a request, copying the headers a UAS must echo.
func (gateway *Gateway) respond(
	request *sip.Message,
	source *net.UDPAddr,
	status int,
	extra map[string]string,
	body []byte,
) {
	response := &sip.Message{IsResponse: true, StatusCode: status}
	// Via, From, To, Call-ID and CSeq are echoed verbatim: a client matches the
	// response to its transaction by exactly these.
	for _, via := range request.All("Via") {
		response.Add("Via", via)
	}
	response.Add("From", request.Get("From"))
	response.Add("To", request.Get("To"))
	response.Add("Call-ID", request.CallID())
	response.Add("CSeq", request.Get("CSeq"))
	// Set, not Add: a caller overriding To to attach the local tag must replace
	// the echoed value. Two To headers would leave the client reading the first,
	// untagged one, and the dialog would never be established.
	for name, value := range extra {
		response.Set(name, value)
	}
	if len(body) > 0 {
		response.Add("Content-Type", "application/sdp")
		response.Body = body
	}
	gateway.send(response, source)
}

func (gateway *Gateway) send(message *sip.Message, target *net.UDPAddr) {
	if gateway.conn == nil || target == nil {
		return
	}
	if _, err := gateway.conn.WriteToUDP(message.Encode(), target); err != nil {
		gateway.logger.Warn("SIP send failed", "target", target.String(), "error", err)
	}
}

// localAddressFor picks the address to advertise to a given peer. Deriving it
// from the route to that peer is what makes a multi-homed host work; a fixed
// value would hand a phone on one subnet an address on another.
func (gateway *Gateway) localAddressFor(peer net.IP) net.IP {
	if gateway.advertise != nil {
		return gateway.advertise
	}
	if peer != nil {
		if conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: peer, Port: 9}); err == nil {
			local := conn.LocalAddr().(*net.UDPAddr).IP
			_ = conn.Close()
			if local != nil && !local.IsUnspecified() {
				return local
			}
		}
	}
	if gateway.conn != nil {
		if local, ok := gateway.conn.LocalAddr().(*net.UDPAddr); ok && !local.IP.IsUnspecified() {
			return local.IP
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

// localPort is the port the gateway listens on, for Contact headers.
func (gateway *Gateway) localPort() int {
	if gateway.conn == nil {
		return 5060
	}
	if local, ok := gateway.conn.LocalAddr().(*net.UDPAddr); ok {
		return local.Port
	}
	return 5060
}

func (gateway *Gateway) contactHeader(peer net.IP) string {
	address := gateway.localAddressFor(peer)
	return fmt.Sprintf("<sip:%s@%s>",
		gateway.config.Account.Username,
		net.JoinHostPort(address.String(), strconv.Itoa(gateway.localPort())))
}

// terminate ends a call on both sides and forgets it.
//
// Order matters: the vocat call is hung up first, because leaving it running
// would keep the SIM occupied and bill the operator even after the phone is
// gone. Then the local resources are released.
func (gateway *Gateway) terminate(dlg *dialog, reason string) {
	if dlg.currentState() == stateTerminated {
		gateway.dialogs.remove(dlg)
		return
	}
	if dlg.vocatCallID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := gateway.client.HangupCall(ctx, dlg.deviceID, dlg.vocatCallID); err != nil {
			gateway.logger.Warn("hang up vocat call during teardown",
				"call_id", dlg.vocatCallID, "error", err)
		}
		cancel()
	}
	dlg.close()
	gateway.dialogs.remove(dlg)
	gateway.logger.Info("SIP call ended",
		"sip_call_id", dlg.callID, "vocat_call_id", dlg.vocatCallID, "reason", reason)
}

// rtpListenIP is the address RTP sockets bind. It follows the SIP bind address
// so a gateway restricted to one interface does not open media on another.
func (gateway *Gateway) rtpListenIP() net.IP {
	if gateway.conn == nil {
		return nil
	}
	local, ok := gateway.conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil || local.IP.IsUnspecified() {
		return nil
	}
	return local.IP
}

// startRTP opens a media socket pointed at the peer described by an SDP body.
func (gateway *Gateway) startRTP(media mediaDescription) (*rtp.Session, error) {
	session, err := rtp.Listen(rtp.Options{
		ListenIP: gateway.rtpListenIP(),
		Payload:  media.Payload,
	})
	if err != nil {
		return nil, err
	}
	if err := session.SetRemote(media.Address, media.Port); err != nil {
		session.Close()
		return nil, err
	}
	return session, nil
}
