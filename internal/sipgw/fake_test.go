package sipgw

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vocat-plugin-telephony/internal/vocat"
)

// fakeVocat is enough of vocat's HTTP API to drive the gateway: login, the call
// list, and the three call actions. It records what the gateway asked for so a
// test can assert the mapping from SIP to vocat rather than only observing SIP.
type fakeVocat struct {
	server *httptest.Server

	mu sync.Mutex
	// calls is the list the gateway polls. Tests mutate it to simulate a call
	// being answered or ending.
	calls []vocat.Call
	// transport lets a test exercise the cellular path, which the gateway must
	// refuse to map to SIP.
	transport string

	dialed   []string
	answered []string
	hungUp   []string
	// mediaOpened counts audio bridges established, so a test can assert the
	// bridge was attached rather than only that SIP looked right.
	mediaOpened int
	// dialErr and friends override what vocat returns, so a test can simulate it
	// refusing a call.
	dialErr   bool
	dialNoID  bool
	answerErr bool
}

func newFakeVocat() *fakeVocat {
	fake := &fakeVocat{transport: "vowifi"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "vocat_session", Value: "s", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "vocat_csrf", Value: "c", Path: "/"})
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"csrf_token": "c",
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}})
	})
	mux.HandleFunc("/api/devices/ec20/calls", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		snapshot := map[string]any{
			"device_id": "ec20",
			"transport": fake.transport,
			"calls":     fake.calls,
		}
		fake.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": snapshot})
	})
	mux.HandleFunc("/api/devices/ec20/calls/dial", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Number string `json:"number"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		fake.mu.Lock()
		fake.dialed = append(fake.dialed, request.Number)
		dialErr, noID := fake.dialErr, fake.dialNoID
		fake.mu.Unlock()

		if dialErr {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"code":"vowifi_call_failed","message":"no"}}`))
			return
		}
		callID := "vocat-out-1"
		if noID {
			callID = ""
		}
		fake.addCall(vocat.Call{
			ID: callID, Number: request.Number, Direction: "outgoing",
			State: "dialing", StartedAt: time.Now().UTC(),
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"accepted": true, "call_id": callID,
			"call": map[string]any{"id": callID, "state": "dialing", "direction": "outgoing"},
		}})
	})
	mux.HandleFunc("/api/devices/ec20/calls/answer", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			CallID string `json:"call_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		fake.mu.Lock()
		fake.answered = append(fake.answered, request.CallID)
		answerErr := fake.answerErr
		fake.mu.Unlock()
		if answerErr {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"code":"vowifi_call_failed","message":"no"}}`))
			return
		}
		fake.setState(request.CallID, "active", true)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"accepted": true, "call_id": request.CallID,
			"call": map[string]any{"id": request.CallID, "state": "active"},
		}})
	})
	mux.HandleFunc("/api/devices/ec20/calls/hangup", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			CallID string `json:"call_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		fake.mu.Lock()
		fake.hungUp = append(fake.hungUp, request.CallID)
		fake.mu.Unlock()
		fake.removeCall(request.CallID)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accepted": true}})
	})
	// The audio bridge is part of answering a call: the gateway attaches it before
	// sending 200 OK, so without this endpoint every outbound call would fail at
	// the moment it should connect.
	mux.HandleFunc("/api/devices/ec20/calls/media", func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		fake.mu.Lock()
		fake.mediaOpened++
		fake.mu.Unlock()
		// Hold the socket open and discard whatever arrives; a test only needs the
		// bridge to establish, not to carry audio.
		for {
			if _, _, err := connection.Read(r.Context()); err != nil {
				connection.Close(websocket.StatusNormalClosure, "done")
				return
			}
		}
	})
	fake.server = httptest.NewServer(mux)
	return fake
}

func (fake *fakeVocat) Close() { fake.server.Close() }

func (fake *fakeVocat) client() (*vocat.Client, error) {
	return vocat.New(vocat.Options{
		BaseURL:            fake.server.URL,
		Username:           "admin",
		Password:           "secret",
		InsecureSkipVerify: true,
	})
}

func (fake *fakeVocat) addCall(call vocat.Call) {
	if call.ID == "" {
		return
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for index, existing := range fake.calls {
		if existing.ID == call.ID {
			fake.calls[index] = call
			return
		}
	}
	fake.calls = append(fake.calls, call)
}

func (fake *fakeVocat) setState(callID, state string, mediaReady bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for index, call := range fake.calls {
		if call.ID != callID {
			continue
		}
		call.State = state
		call.MediaReady = mediaReady
		if state == "active" && call.AnsweredAt == nil {
			now := time.Now().UTC()
			call.AnsweredAt = &now
		}
		fake.calls[index] = call
		return
	}
}

func (fake *fakeVocat) removeCall(callID string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	kept := fake.calls[:0]
	for _, call := range fake.calls {
		if call.ID != callID {
			kept = append(kept, call)
		}
	}
	fake.calls = kept
}

func (fake *fakeVocat) snapshot() (dialed, answered, hungUp []string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]string(nil), fake.dialed...),
		append([]string(nil), fake.answered...),
		append([]string(nil), fake.hungUp...)
}

func (fake *fakeVocat) setTransport(transport string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.transport = transport
}

func (fake *fakeVocat) setDialErr(value bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.dialErr = value
}

func (fake *fakeVocat) setDialNoID(value bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.dialNoID = value
}

func (fake *fakeVocat) setAnswerErr(value bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.answerErr = value
}

// softphone is a minimal SIP client over UDP: it sends requests and collects
// responses, so a test can assert what a real phone would observe.
type softphone struct {
	conn    *net.UDPConn
	gateway *net.UDPAddr
}

func newSoftphone(gatewayAddress string) (*softphone, error) {
	target, err := net.ResolveUDPAddr("udp", gatewayAddress)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	return &softphone{conn: conn, gateway: target}, nil
}

func (phone *softphone) Close() { _ = phone.conn.Close() }

func (phone *softphone) address() string {
	local := phone.conn.LocalAddr().(*net.UDPAddr)
	return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", local.Port))
}

func (phone *softphone) send(raw string) error {
	_, err := phone.conn.WriteToUDP([]byte(raw), phone.gateway)
	return err
}
