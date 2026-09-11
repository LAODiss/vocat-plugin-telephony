package rules

import (
	"testing"

	"vocat-plugin-telephony/internal/contacts"
)

func book() *contacts.Book {
	return contacts.NewBook([]contacts.Contact{
		{Number: "+447700900123", Name: "Alice"},
		{Number: "10086", Name: "Carrier"},
	})
}

func TestFirstMatchingRuleWins(t *testing.T) {
	// An allow-then-block-everything policy is the main thing ordering has to
	// express correctly.
	engine := NewEngine([]Rule{
		{ID: "allow-contacts", Enabled: true, Match: MatchContact, Action: ActionAllow},
		{ID: "block-rest", Enabled: true, Match: MatchAny, Action: ActionReject},
	}, book(), ActionAllow)

	known := engine.Evaluate("ec20", "07700900123")
	if known.Action != ActionAllow || known.RuleID != "allow-contacts" {
		t.Fatalf("known caller decision = %+v", known)
	}
	if known.ContactName != "Alice" {
		t.Fatalf("ContactName = %q, want Alice", known.ContactName)
	}
	unknown := engine.Evaluate("ec20", "+447700111222")
	if unknown.Action != ActionReject || unknown.RuleID != "block-rest" {
		t.Fatalf("unknown caller decision = %+v", unknown)
	}
}

func TestDisabledRulesAreIgnored(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "off", Enabled: false, Match: MatchAny, Action: ActionReject},
	}, book(), ActionAllow)
	if decision := engine.Evaluate("ec20", "+447700111222"); decision.Action != ActionAllow {
		t.Fatalf("a disabled rule was applied: %+v", decision)
	}
}

func TestDeviceScopedRuleOnlyAppliesToItsDevice(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "only-ec25", Enabled: true, DeviceID: "ec25", Match: MatchAny, Action: ActionReject},
	}, book(), ActionAllow)
	if decision := engine.Evaluate("ec25", "+1"); decision.Action != ActionReject {
		t.Fatalf("scoped rule did not apply to its own device: %+v", decision)
	}
	if decision := engine.Evaluate("ec20", "+1"); decision.Action != ActionAllow {
		t.Fatalf("scoped rule leaked to another device: %+v", decision)
	}
}

func TestPrefixMatchUsesDigitsOnly(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "block-uk-premium", Enabled: true, Match: MatchPrefix, Value: "4490", Action: ActionReject},
	}, book(), ActionAllow)
	if decision := engine.Evaluate("ec20", "+44 9012 345678"); decision.Action != ActionReject {
		t.Fatalf("prefix rule did not match a formatted number: %+v", decision)
	}
	if decision := engine.Evaluate("ec20", "+447700900123"); decision.Action != ActionAllow {
		t.Fatalf("prefix rule over-matched: %+v", decision)
	}
}

func TestNumberMatchIsFormatInsensitive(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "vip", Enabled: true, Match: MatchNumber, Value: "+447700900123", Action: ActionAnswer},
	}, book(), ActionReject)
	if decision := engine.Evaluate("ec20", "07700900123"); decision.Action != ActionAnswer {
		t.Fatalf("number rule did not match the national form: %+v", decision)
	}
}

func TestUnknownAndAnonymousDoNotOverlap(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "anon", Enabled: true, Match: MatchAnonymous, Action: ActionReject},
		{ID: "unknown", Enabled: true, Match: MatchUnknown, Action: ActionVoicemail},
	}, book(), ActionAllow)

	if decision := engine.Evaluate("ec20", "anonymous"); decision.RuleID != "anon" {
		t.Fatalf("withheld caller matched %q, want anon", decision.RuleID)
	}
	if decision := engine.Evaluate("ec20", ""); decision.RuleID != "anon" {
		t.Fatalf("empty caller matched %q, want anon", decision.RuleID)
	}
	// A real number absent from the book is "unknown", not "anonymous".
	if decision := engine.Evaluate("ec20", "+447700111222"); decision.RuleID != "unknown" {
		t.Fatalf("unknown caller matched %q, want unknown", decision.RuleID)
	}
	// A known contact matches neither.
	if decision := engine.Evaluate("ec20", "10086"); decision.Action != ActionAllow {
		t.Fatalf("known contact matched a rule: %+v", decision)
	}
}

func TestFallbackAppliesWhenNothingMatches(t *testing.T) {
	engine := NewEngine(nil, book(), ActionReject)
	decision := engine.Evaluate("ec20", "+447700111222")
	if decision.Action != ActionReject || decision.RuleID != "" {
		t.Fatalf("fallback decision = %+v", decision)
	}
	// An empty fallback must default to allow rather than silently rejecting
	// every call.
	if got := NewEngine(nil, book(), "").Evaluate("ec20", "+1").Action; got != ActionAllow {
		t.Fatalf("empty fallback = %q, want allow", got)
	}
}

func TestDelayIsCarriedThrough(t *testing.T) {
	engine := NewEngine([]Rule{
		{ID: "vm", Enabled: true, Match: MatchAny, Action: ActionVoicemail, DelaySeconds: 20},
	}, book(), ActionAllow)
	if decision := engine.Evaluate("ec20", "+1"); decision.DelaySeconds != 20 {
		t.Fatalf("DelaySeconds = %d, want 20", decision.DelaySeconds)
	}
}

func TestIsAnonymous(t *testing.T) {
	for _, value := range []string{"", "  ", "anonymous", "Anonymous", "unavailable", "restricted", "private", "withheld", "Unknown", "+++"} {
		if !IsAnonymous(value) {
			t.Fatalf("IsAnonymous(%q) = false", value)
		}
	}
	for _, value := range []string{"+447700900123", "10086", "07700900123"} {
		if IsAnonymous(value) {
			t.Fatalf("IsAnonymous(%q) = true", value)
		}
	}
}

func TestValidate(t *testing.T) {
	valid := []Rule{
		{Match: MatchAny, Action: ActionAllow},
		{Match: MatchNumber, Value: "+447700900123", Action: ActionReject},
		{Match: MatchPrefix, Value: "44", Action: ActionVoicemail, DelaySeconds: 30},
		{Match: MatchContact, Action: ActionAnswer},
		{Match: MatchUnknown, Action: ActionReject},
		{Match: MatchAnonymous, Action: ActionReject},
	}
	for index, rule := range valid {
		if err := Validate(rule); err != nil {
			t.Fatalf("valid rule %d rejected: %v", index, err)
		}
	}
	invalid := map[string]Rule{
		"unknown action":   {Match: MatchAny, Action: "explode"},
		"unknown match":    {Match: "sideways", Action: ActionAllow},
		"value on any":     {Match: MatchAny, Value: "44", Action: ActionAllow},
		"number no digits": {Match: MatchNumber, Value: "abc", Action: ActionAllow},
		"prefix no digits": {Match: MatchPrefix, Value: "", Action: ActionAllow},
		"negative delay":   {Match: MatchAny, Action: ActionAllow, DelaySeconds: -1},
		"excessive delay":  {Match: MatchAny, Action: ActionAllow, DelaySeconds: 121},
		"long note":        {Match: MatchAny, Action: ActionAllow, Note: string(make([]byte, 201))},
	}
	for name, rule := range invalid {
		if err := Validate(rule); err == nil {
			t.Fatalf("%s: Validate() must fail", name)
		}
	}
}

func TestNeedsCredentials(t *testing.T) {
	// Allow-only policies need no privileges, so the panel should not nag.
	if NeedsCredentials([]Rule{{Enabled: true, Match: MatchAny, Action: ActionAllow}}) {
		t.Fatal("an allow-only policy must not require credentials")
	}
	if NeedsCredentials([]Rule{{Enabled: false, Match: MatchAny, Action: ActionReject}}) {
		t.Fatal("a disabled rule must not require credentials")
	}
	for _, action := range []Action{ActionReject, ActionAnswer, ActionVoicemail} {
		if !NeedsCredentials([]Rule{{Enabled: true, Match: MatchAny, Action: action}}) {
			t.Fatalf("action %q must require credentials", action)
		}
	}
}
