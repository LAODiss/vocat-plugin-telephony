// Package notify renders and delivers notification messages.
//
// vocat has seven notification channels, but a plugin cannot borrow them: the
// only plugin-reachable send path is the settings "test" endpoint, whose body is
// hard-coded, and every channel secret comes back masked as "********" from
// GET /api/settings/notifications. So this package ships its own senders.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event identifies what happened, so a template can be chosen per event.
type Event string

const (
	EventIncoming  Event = "call.incoming"
	EventRejected  Event = "call.rejected"
	EventAnswered  Event = "call.answered"
	EventMissed    Event = "call.missed"
	EventVoicemail Event = "call.voicemail"
	EventKeepalive Event = "keepalive.result"
	EventTest      Event = "test"
)

// AllEvents is the set a template may be configured for.
var AllEvents = []Event{
	EventIncoming, EventRejected, EventAnswered, EventMissed, EventVoicemail, EventKeepalive,
}

// Template is one event's title and body, with {{placeholder}} substitution
// matching vocat's own webhook template syntax.
type Template struct {
	Event   Event  `json:"event"`
	Enabled bool   `json:"enabled"`
	Title   string `json:"title"`
	Body    string `json:"body"`
}

// Fields are the values a template can interpolate.
type Fields struct {
	Event       Event
	DeviceID    string
	DeviceName  string
	Caller      string
	Called      string
	ContactName string
	Action      string
	RuleID      string
	Duration    string
	Recording   string
	Result      string
	Time        time.Time
}

// Placeholders returns the substitution map. Exposed so the UI can list the
// available names instead of documenting them separately.
func (fields Fields) Placeholders() map[string]string {
	when := fields.Time
	if when.IsZero() {
		when = time.Now()
	}
	caller := strings.TrimSpace(fields.Caller)
	if caller == "" {
		caller = "未知号码"
	}
	display := strings.TrimSpace(fields.ContactName)
	if display == "" {
		display = caller
	}
	return map[string]string{
		"{{event}}":       string(fields.Event),
		"{{device_id}}":   fields.DeviceID,
		"{{device_name}}": fields.DeviceName,
		"{{caller}}":      caller,
		"{{number}}":      caller,
		"{{called}}":      fields.Called,
		"{{contact}}":     display,
		"{{display}}":     display,
		"{{action}}":      fields.Action,
		"{{rule}}":        fields.RuleID,
		"{{duration}}":    fields.Duration,
		"{{recording}}":   fields.Recording,
		"{{result}}":      fields.Result,
		"{{time}}":        when.Local().Format("2006-01-02 15:04:05"),
		"{{timestamp}}":   when.UTC().Format(time.RFC3339),
	}
}

// Render substitutes placeholders. Unknown {{names}} are left verbatim, which
// makes a typo visible in the delivered message rather than silently empty.
func Render(text string, fields Fields) string {
	for placeholder, value := range fields.Placeholders() {
		text = strings.ReplaceAll(text, placeholder, value)
	}
	return text
}

// DefaultTemplates are the built-in messages, used when an event has no
// configured template.
func DefaultTemplates() []Template {
	return []Template{
		{Event: EventIncoming, Enabled: true, Title: "收到来电",
			Body: "📞 {{display}}\n设备  {{device_name}}\n号码  {{caller}}\n时间  {{time}}"},
		{Event: EventRejected, Enabled: true, Title: "已自动拒接",
			Body: "🚫 {{display}}\n设备  {{device_name}}\n号码  {{caller}}\n规则  {{rule}}\n时间  {{time}}"},
		{Event: EventAnswered, Enabled: false, Title: "已自动接听",
			Body: "✅ {{display}}\n设备  {{device_name}}\n号码  {{caller}}\n时间  {{time}}"},
		{Event: EventMissed, Enabled: true, Title: "未接来电",
			Body: "☎️ {{display}}\n设备  {{device_name}}\n号码  {{caller}}\n时间  {{time}}"},
		{Event: EventVoicemail, Enabled: true, Title: "新的语音留言",
			Body: "🎙 {{display}}\n设备  {{device_name}}\n号码  {{caller}}\n时长  {{duration}}\n时间  {{time}}"},
		{Event: EventKeepalive, Enabled: true, Title: "保号任务结果",
			Body: "🔄 {{device_name}}\n结果  {{result}}\n时间  {{time}}"},
	}
}

// Config is the plugin's own notification configuration.
type Config struct {
	Webhook  WebhookConfig  `json:"webhook"`
	Telegram TelegramConfig `json:"telegram"`
	PushPlus PushPlusConfig `json:"pushplus"`
	// Templates are keyed by event; a missing event falls back to the default.
	Templates []Template `json:"templates"`
}

type WebhookConfig struct {
	Enabled bool     `json:"enabled"`
	URLs    []string `json:"urls"`
	Secret  string   `json:"secret,omitempty"`
}

type TelegramConfig struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token,omitempty"`
	ChatID   string `json:"chat_id"`
}

type PushPlusConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
	Topic   string `json:"topic,omitempty"`
}

// TemplateFor returns the configured template for an event, or the default.
func (config Config) TemplateFor(event Event) Template {
	for _, template := range config.Templates {
		if template.Event == event {
			return template
		}
	}
	for _, template := range DefaultTemplates() {
		if template.Event == event {
			return template
		}
	}
	return Template{Event: event, Enabled: false, Title: string(event), Body: "{{event}} {{caller}}"}
}

// Sender delivers rendered messages to the configured channels.
type Sender struct {
	client *http.Client
}

func NewSender() *Sender {
	return &Sender{client: newRestrictedClient(10 * time.Second)}
}

// Result reports per-channel delivery outcomes so the UI can show which
// channel failed rather than a single opaque error.
type Result struct {
	Channel string `json:"channel"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// Send delivers one event to every enabled channel. A disabled template
// suppresses the event entirely and returns no results.
func (sender *Sender) Send(ctx context.Context, config Config, fields Fields) []Result {
	template := config.TemplateFor(fields.Event)
	// A test push must go out even when the event's template is switched off,
	// otherwise "test" would silently do nothing.
	if !template.Enabled && fields.Event != EventTest {
		return nil
	}
	title := Render(template.Title, fields)
	body := Render(template.Body, fields)

	var results []Result
	if config.Webhook.Enabled && len(config.Webhook.URLs) > 0 {
		results = append(results, sender.sendWebhook(ctx, config.Webhook, fields, title, body))
	}
	if config.Telegram.Enabled {
		results = append(results, sender.sendTelegram(ctx, config.Telegram, title, body))
	}
	if config.PushPlus.Enabled {
		results = append(results, sender.sendPushPlus(ctx, config.PushPlus, title, body))
	}
	return results
}

func (sender *Sender) sendWebhook(ctx context.Context, config WebhookConfig, fields Fields, title, body string) Result {
	payload, err := json.Marshal(map[string]any{
		"event":       string(fields.Event),
		"title":       title,
		"message":     body,
		"device_id":   fields.DeviceID,
		"device_name": fields.DeviceName,
		"caller":      fields.Caller,
		"called":      fields.Called,
		"contact":     fields.ContactName,
		"action":      fields.Action,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return Result{Channel: "webhook", Error: err.Error()}
	}
	var failures []string
	for _, raw := range config.URLs {
		target, validateErr := validateOutboundURL(raw)
		if validateErr != nil {
			failures = append(failures, validateErr.Error())
			continue
		}
		request, buildErr := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
		if buildErr != nil {
			failures = append(failures, buildErr.Error())
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "vocat-telephony-plugin/1")
		if config.Secret != "" {
			digest := hmac.New(sha256.New, []byte(config.Secret))
			digest.Write(payload)
			request.Header.Set("X-Vocat-Signature", "sha256="+hex.EncodeToString(digest.Sum(nil)))
		}
		if err := sender.execute(request); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return Result{Channel: "webhook", Error: strings.Join(failures, "; ")}
	}
	return Result{Channel: "webhook", OK: true}
}

func (sender *Sender) sendTelegram(ctx context.Context, config TelegramConfig, title, body string) Result {
	if strings.TrimSpace(config.BotToken) == "" || strings.TrimSpace(config.ChatID) == "" {
		return Result{Channel: "telegram", Error: "bot_token 和 chat_id 都是必填项"}
	}
	payload, err := json.Marshal(map[string]any{
		"chat_id": config.ChatID,
		"text":    strings.TrimSpace(title + "\n" + body),
	})
	if err != nil {
		return Result{Channel: "telegram", Error: err.Error()}
	}
	endpoint := "https://api.telegram.org/bot" + url.PathEscape(config.BotToken) + "/sendMessage"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{Channel: "telegram", Error: err.Error()}
	}
	request.Header.Set("Content-Type", "application/json")
	if err := sender.execute(request); err != nil {
		return Result{Channel: "telegram", Error: err.Error()}
	}
	return Result{Channel: "telegram", OK: true}
}

func (sender *Sender) sendPushPlus(ctx context.Context, config PushPlusConfig, title, body string) Result {
	if strings.TrimSpace(config.Token) == "" {
		return Result{Channel: "pushplus", Error: "token 是必填项"}
	}
	document := map[string]any{"token": config.Token, "title": title, "content": body}
	if config.Topic != "" {
		document["topic"] = config.Topic
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return Result{Channel: "pushplus", Error: err.Error()}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://www.pushplus.plus/send", bytes.NewReader(payload))
	if err != nil {
		return Result{Channel: "pushplus", Error: err.Error()}
	}
	request.Header.Set("Content-Type", "application/json")
	if err := sender.execute(request); err != nil {
		return Result{Channel: "pushplus", Error: err.Error()}
	}
	return Result{Channel: "pushplus", OK: true}
}

func (sender *Sender) execute(request *http.Request) error {
	response, err := sender.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		text := strings.TrimSpace(string(raw))
		if text == "" {
			return fmt.Errorf("HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, text)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	return nil
}

// ValidateConfig checks a configuration before storing it.
func ValidateConfig(config Config) error {
	for _, raw := range config.Webhook.URLs {
		if _, err := validateOutboundURL(raw); err != nil {
			return err
		}
	}
	for _, template := range config.Templates {
		if len(template.Title) > 200 {
			return errors.New("notification title must be 200 characters or fewer")
		}
		if len(template.Body) > 4000 {
			return errors.New("notification body must be 4000 characters or fewer")
		}
		known := false
		for _, event := range AllEvents {
			if template.Event == event {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("unknown notification event %q", template.Event)
		}
	}
	return nil
}

// validateOutboundURL keeps a webhook target from becoming a way to probe the
// host's private networks.
func validateOutboundURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("webhook URL is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse webhook URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("webhook URL scheme %q is not supported", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return "", errors.New("webhook URL has no host")
	}
	if parsed.User != nil {
		return "", errors.New("webhook URL must not embed credentials")
	}
	return parsed.String(), nil
}

// newRestrictedClient ignores ambient proxy settings and refuses private
// destinations at dial time, so a webhook cannot be aimed at the host's own
// services or a cloud metadata endpoint.
func newRestrictedClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if ip := net.ParseIP(host); ip != nil && isRestricted(ip) {
					return nil, fmt.Errorf("notify: refusing to reach restricted address %s", ip)
				}
				return dialer.DialContext(ctx, network, address)
			},
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func isRestricted(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// 100.64.0.0/10 (CGNAT) is not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}
