package notify

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRenderSubstitutesEveryDocumentedPlaceholder(t *testing.T) {
	fields := Fields{
		Event: EventIncoming, DeviceID: "ec20", DeviceName: "Bench EC20",
		Caller: "+447700900123", Called: "+447700900000", ContactName: "Alice",
		Action: "reject", RuleID: "r1", Duration: "0:42", Result: "success",
		Time: time.Date(2026, 9, 1, 12, 34, 56, 0, time.UTC),
	}
	for placeholder := range fields.Placeholders() {
		rendered := Render(placeholder, fields)
		if strings.Contains(rendered, "{{") {
			t.Fatalf("placeholder %s was not substituted (got %q)", placeholder, rendered)
		}
	}
	// {{contact}} must prefer the contact name over the raw number.
	if got := Render("{{contact}}", fields); got != "Alice" {
		t.Fatalf("{{contact}} = %q, want Alice", got)
	}
	if got := Render("{{caller}}", fields); got != "+447700900123" {
		t.Fatalf("{{caller}} = %q", got)
	}
}

func TestRenderFallsBackWhenIdentityIsMissing(t *testing.T) {
	// A withheld caller must not render as an empty string in a notification.
	fields := Fields{Event: EventIncoming}
	if got := Render("{{caller}}", fields); got != "未知号码" {
		t.Fatalf("{{caller}} = %q, want the unknown-number placeholder", got)
	}
	if got := Render("{{contact}}", fields); got != "未知号码" {
		t.Fatalf("{{contact}} = %q", got)
	}
}

func TestUnknownPlaceholderIsLeftVisible(t *testing.T) {
	// Leaving a typo verbatim makes it obvious in the delivered message; silently
	// blanking it would hide the mistake.
	got := Render("hello {{nope}}", Fields{Event: EventTest})
	if got != "hello {{nope}}" {
		t.Fatalf("Render() = %q", got)
	}
}

func TestTemplateForFallsBackToDefaults(t *testing.T) {
	config := Config{}
	for _, event := range AllEvents {
		template := config.TemplateFor(event)
		if template.Event != event {
			t.Fatalf("TemplateFor(%s).Event = %s", event, template.Event)
		}
		if strings.TrimSpace(template.Body) == "" {
			t.Fatalf("default template for %s has no body", event)
		}
	}
	// A configured template wins over the default.
	config.Templates = []Template{{Event: EventMissed, Enabled: true, Title: "T", Body: "B"}}
	if got := config.TemplateFor(EventMissed); got.Title != "T" || got.Body != "B" {
		t.Fatalf("configured template not used: %+v", got)
	}
}

func TestDefaultTemplatesCoverEveryEvent(t *testing.T) {
	defaults := DefaultTemplates()
	for _, event := range AllEvents {
		found := false
		for _, template := range defaults {
			if template.Event == event {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no default template for %s", event)
		}
	}
}

func TestSendSkipsADisabledEventButNotATest(t *testing.T) {
	sender := NewSender()
	config := Config{
		Webhook:   WebhookConfig{Enabled: true, URLs: []string{"https://example.invalid/hook"}},
		Templates: []Template{{Event: EventIncoming, Enabled: false, Title: "T", Body: "B"}},
	}
	if results := sender.Send(context.Background(), config, Fields{Event: EventIncoming}); results != nil {
		t.Fatalf("a disabled template must suppress the event, got %+v", results)
	}
	// A test push must go out regardless, or "test" would be a silent no-op.
	results := sender.Send(context.Background(), config, Fields{Event: EventTest})
	if len(results) == 0 {
		t.Fatal("a test send must attempt delivery")
	}
}

func TestSendReportsMissingChannelCredentials(t *testing.T) {
	sender := NewSender()
	config := Config{
		Telegram:  TelegramConfig{Enabled: true},
		PushPlus:  PushPlusConfig{Enabled: true},
		Templates: []Template{{Event: EventTest, Enabled: true, Title: "T", Body: "B"}},
	}
	results := sender.Send(context.Background(), config, Fields{Event: EventTest})
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.OK || result.Error == "" {
			t.Fatalf("channel %s should report a configuration error: %+v", result.Channel, result)
		}
	}
}

func TestValidateConfigRejectsUnsafeWebhookTargets(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":       "",
		"no scheme":   "example.com/hook",
		"file scheme": "file:///etc/passwd",
		"credentials": "https://user:pass@example.com/hook",
		"no host":     "https:///hook",
	} {
		config := Config{Webhook: WebhookConfig{URLs: []string{raw}}}
		if err := ValidateConfig(config); err == nil {
			t.Fatalf("%s: ValidateConfig(%q) must fail", name, raw)
		}
	}
	if err := ValidateConfig(Config{Webhook: WebhookConfig{URLs: []string{"https://example.com/hook"}}}); err != nil {
		t.Fatalf("ValidateConfig(valid) = %v", err)
	}
}

func TestValidateConfigChecksTemplates(t *testing.T) {
	if err := ValidateConfig(Config{Templates: []Template{{Event: "made.up"}}}); err == nil {
		t.Fatal("an unknown event must be rejected")
	}
	if err := ValidateConfig(Config{Templates: []Template{
		{Event: EventIncoming, Title: string(make([]byte, 201))},
	}}); err == nil {
		t.Fatal("an over-long title must be rejected")
	}
	if err := ValidateConfig(Config{Templates: []Template{
		{Event: EventIncoming, Body: string(make([]byte, 4001))},
	}}); err == nil {
		t.Fatal("an over-long body must be rejected")
	}
}

func TestRestrictedClientRefusesPrivateWebhookTargets(t *testing.T) {
	// A webhook must not become a way to probe the host's own services.
	sender := NewSender()
	config := Config{
		Webhook:   WebhookConfig{Enabled: true, URLs: []string{"http://127.0.0.1:9/hook"}},
		Templates: []Template{{Event: EventTest, Enabled: true, Title: "T", Body: "B"}},
	}
	results := sender.Send(context.Background(), config, Fields{Event: EventTest})
	if len(results) != 1 || results[0].OK {
		t.Fatalf("loopback webhook should fail: %+v", results)
	}
	if !strings.Contains(results[0].Error, "restricted") {
		t.Fatalf("error should name the restriction, got %q", results[0].Error)
	}
}
