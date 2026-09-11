package vocat

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Call mirrors vocat's serialised vowifi.Call.
type Call struct {
	ID         string     `json:"id"`
	Number     string     `json:"number"`
	Direction  string     `json:"direction"`
	State      string     `json:"state"`
	StartedAt  time.Time  `json:"started_at"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	SIPCode    int        `json:"sip_code,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	MediaReady bool       `json:"media_ready,omitempty"`
	Codec      string     `json:"codec,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

// Live reports whether the call still occupies the line.
func (call Call) Live() bool {
	return call.State != "ended" && call.State != "failed"
}

// Ringing reports whether this is an inbound call waiting to be answered.
func (call Call) Ringing() bool {
	return call.Direction == "incoming" && call.State == "ringing"
}

// CallsSnapshot is the shape of GET /api/devices/{id}/calls.
//
// Note the cellular transport returns a different, AT-derived call shape, so
// Calls is only meaningful when Transport is "vowifi".
type CallsSnapshot struct {
	DeviceID  string `json:"device_id"`
	Transport string `json:"transport"`
	Calls     []Call `json:"calls"`
	Raw       string `json:"raw,omitempty"`
}

// Device is the subset of vocat's device summary this plugin needs.
type Device struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DeviceType    string `json:"device_type"`
	Running       bool   `json:"running"`
	Healthy       bool   `json:"healthy"`
	VoWiFiEnabled bool   `json:"vowifi_enabled"`
	VoWiFiActive  bool   `json:"vowifi_active"`
	LocalPhone    string `json:"local_phone"`
	Modem         struct {
		ICCID       string `json:"iccid"`
		IMSI        string `json:"imsi"`
		IMEI        string `json:"imei"`
		PhoneNumber string `json:"phone_number"`
		Operator    string `json:"operator"`
	} `json:"modem"`
}

// Devices lists configured devices.
func (client *Client) Devices(ctx context.Context) ([]Device, error) {
	var response struct {
		Data struct {
			Devices []Device `json:"devices"`
		} `json:"data"`
	}
	if err := client.Get(ctx, "/api/devices", &response); err != nil {
		return nil, err
	}
	return response.Data.Devices, nil
}

// Calls reads the current call list for a device.
func (client *Client) Calls(ctx context.Context, deviceID string) (CallsSnapshot, error) {
	var response struct {
		Data CallsSnapshot `json:"data"`
	}
	path := "/api/devices/" + url.PathEscape(deviceID) + "/calls"
	if err := client.Get(ctx, path, &response); err != nil {
		return CallsSnapshot{}, err
	}
	return response.Data, nil
}

// AnswerCall answers a ringing call. An empty callID lets vocat resolve the
// first call whose state is exactly "ringing".
func (client *Client) AnswerCall(ctx context.Context, deviceID, callID string) (Call, error) {
	return client.callAction(ctx, deviceID, "answer", map[string]any{"call_id": callID})
}

// HangupCall ends a call. On a ringing inbound call vocat responds with SIP 486
// Busy Here; there is no API to choose a different rejection code.
func (client *Client) HangupCall(ctx context.Context, deviceID, callID string) error {
	_, err := client.callAction(ctx, deviceID, "hangup", map[string]any{"call_id": callID})
	return err
}

// DialCall places an outbound call. durationSeconds of 0 means no automatic
// hang-up; vocat caps it at 600.
func (client *Client) DialCall(ctx context.Context, deviceID, number string, durationSeconds int) (Call, error) {
	return client.callAction(ctx, deviceID, "dial", map[string]any{
		"number": number, "duration_seconds": durationSeconds,
	})
}

func (client *Client) callAction(ctx context.Context, deviceID, action string, body map[string]any) (Call, error) {
	var response struct {
		Data struct {
			Accepted bool   `json:"accepted"`
			CallID   string `json:"call_id"`
			Call     *Call  `json:"call"`
		} `json:"data"`
	}
	path := "/api/devices/" + url.PathEscape(deviceID) + "/calls/" + action
	if err := client.Post(ctx, path, body, &response); err != nil {
		return Call{}, err
	}
	if response.Data.Call != nil {
		return *response.Data.Call, nil
	}
	return Call{ID: response.Data.CallID}, nil
}

// MediaURL builds the WebSocket URL for a call's PCM bridge.
func (client *Client) MediaURL(deviceID, callID string) string {
	scheme := "wss"
	if strings.EqualFold(client.base.Scheme, "http") {
		scheme = "ws"
	}
	return fmt.Sprintf("%s://%s/api/devices/%s/calls/media?call_id=%s",
		scheme, client.base.Host, url.PathEscape(deviceID), url.QueryEscape(callID))
}
