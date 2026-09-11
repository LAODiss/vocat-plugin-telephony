// Package rules decides what to do with an incoming call.
//
// The engine is intentionally small and total: every call produces exactly one
// decision, and the decision records which rule produced it so the operator can
// see why a call was rejected. Rules are evaluated in order and the first match
// wins, which makes an allow-then-block-everything policy expressible without
// any precedence subtleties.
package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"vocat-plugin-telephony/internal/contacts"
)

// Action is what to do with a matched call.
type Action string

const (
	// ActionAllow lets the call ring untouched. This is the safe default and the
	// only action that requires no privileges.
	ActionAllow Action = "allow"
	// ActionReject hangs up. On a ringing inbound call vocat sends SIP 486 Busy
	// Here; there is no API to choose another code.
	ActionReject Action = "reject"
	// ActionAnswer answers the call.
	ActionAnswer Action = "answer"
	// ActionVoicemail answers the call and records the caller.
	ActionVoicemail Action = "voicemail"
)

// Match is how a rule selects calls.
type Match string

const (
	// MatchAny matches every call. Used for the catch-all default rule.
	MatchAny Match = "any"
	// MatchNumber matches one subscriber, comparing significant digits so the
	// same person matches in E.164 and national forms.
	MatchNumber Match = "number"
	// MatchPrefix matches a leading digit string, for country or operator ranges.
	MatchPrefix Match = "prefix"
	// MatchContact matches any number in the address book.
	MatchContact Match = "contact"
	// MatchUnknown matches numbers absent from the address book.
	MatchUnknown Match = "unknown"
	// MatchAnonymous matches withheld or empty caller identities.
	MatchAnonymous Match = "anonymous"
)

// Rule is one ordered policy entry.
type Rule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Match   Match  `json:"match"`
	Value   string `json:"value,omitempty"`
	Action  Action `json:"action"`
	// DeviceID restricts the rule to one device. Empty means every device.
	DeviceID string `json:"device_id,omitempty"`
	// DelaySeconds waits before acting, so a human can pick up first. It applies
	// to answer and voicemail; a reject is immediate.
	DelaySeconds int    `json:"delay_seconds,omitempty"`
	Note         string `json:"note,omitempty"`
}

// Decision is the outcome of evaluating a call.
type Decision struct {
	Action       Action
	RuleID       string
	Match        Match
	DelaySeconds int
	// ContactName is filled when the caller is in the address book, so the
	// caller does not have to look it up again.
	ContactName string
}

// Engine evaluates rules against calls.
type Engine struct {
	rules []Rule
	book  *contacts.Book
	// fallback applies when no rule matches. Allow keeps a misconfigured policy
	// from silently swallowing every call.
	fallback Action
}

// NewEngine builds an engine. Disabled rules are dropped at construction so
// evaluation stays a simple ordered scan.
func NewEngine(ruleList []Rule, book *contacts.Book, fallback Action) *Engine {
	active := make([]Rule, 0, len(ruleList))
	for _, rule := range ruleList {
		if rule.Enabled {
			active = append(active, rule)
		}
	}
	if fallback == "" {
		fallback = ActionAllow
	}
	return &Engine{rules: active, book: book, fallback: fallback}
}

// Evaluate returns the decision for an incoming call.
func (engine *Engine) Evaluate(deviceID, number string) Decision {
	name := ""
	if engine.book != nil {
		if contact, ok := engine.book.Lookup(number); ok {
			name = contact.Name
		}
	}
	for _, rule := range engine.rules {
		if rule.DeviceID != "" && rule.DeviceID != deviceID {
			continue
		}
		if !engine.matches(rule, number, name != "") {
			continue
		}
		return Decision{
			Action: rule.Action, RuleID: rule.ID, Match: rule.Match,
			DelaySeconds: rule.DelaySeconds, ContactName: name,
		}
	}
	return Decision{Action: engine.fallback, RuleID: "", Match: "", ContactName: name}
}

func (engine *Engine) matches(rule Rule, number string, known bool) bool {
	switch rule.Match {
	case MatchAny:
		return true
	case MatchAnonymous:
		return IsAnonymous(number)
	case MatchNumber:
		return contacts.SameNumber(rule.Value, number)
	case MatchPrefix:
		prefix := contacts.Digits(rule.Value)
		if prefix == "" {
			return false
		}
		return strings.HasPrefix(contacts.Digits(number), prefix)
	case MatchContact:
		return known
	case MatchUnknown:
		// An anonymous call is reported separately; treating it as "unknown"
		// too would make the two match kinds overlap confusingly.
		return !known && !IsAnonymous(number)
	default:
		return false
	}
}

// IsAnonymous reports whether a caller identity was withheld. IMS presents this
// in several forms depending on the carrier.
func IsAnonymous(number string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(number))
	if trimmed == "" {
		return true
	}
	for _, marker := range []string{"anonymous", "unavailable", "restricted", "private", "withheld", "unknown"} {
		if strings.Contains(trimmed, marker) {
			return true
		}
	}
	// A caller identity with no digits at all cannot be dialled back and is
	// effectively anonymous.
	return contacts.Digits(trimmed) == ""
}

// Validate checks a rule before storing it.
func Validate(rule Rule) error {
	switch rule.Action {
	case ActionAllow, ActionReject, ActionAnswer, ActionVoicemail:
	default:
		return fmt.Errorf("unknown action %q", rule.Action)
	}
	switch rule.Match {
	case MatchAny, MatchContact, MatchUnknown, MatchAnonymous:
		if strings.TrimSpace(rule.Value) != "" {
			return fmt.Errorf("match %q does not take a value", rule.Match)
		}
	case MatchNumber, MatchPrefix:
		if contacts.Digits(rule.Value) == "" {
			return fmt.Errorf("match %q requires a numeric value", rule.Match)
		}
		if len(rule.Value) > 40 {
			return errors.New("rule value must be 40 characters or fewer")
		}
	default:
		return fmt.Errorf("unknown match %q", rule.Match)
	}
	if rule.DelaySeconds < 0 || rule.DelaySeconds > 120 {
		return errors.New("delay_seconds must be between 0 and 120")
	}
	if len(rule.Note) > 200 {
		return errors.New("rule note must be 200 characters or fewer")
	}
	return nil
}

// NeedsCredentials reports whether a rule requires the plugin to act on vocat's
// API by itself. Allow needs nothing; the rest need an authenticated session.
func NeedsCredentials(ruleList []Rule) bool {
	for _, rule := range ruleList {
		if !rule.Enabled {
			continue
		}
		if rule.Action != ActionAllow {
			return true
		}
	}
	return false
}

// Sorted returns rules in evaluation order for display. Order is the stored
// order; this only makes the intent explicit at call sites.
func Sorted(ruleList []Rule) []Rule {
	sorted := append([]Rule(nil), ruleList...)
	sort.SliceStable(sorted, func(i, j int) bool { return i < j })
	return sorted
}
