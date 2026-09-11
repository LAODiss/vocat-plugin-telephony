// Registrar tracks which softphones are reachable for a SIP account.
//
// A single account may register from several devices at once — a phone and a
// desktop client is the common case — so bindings are a set keyed by contact URI
// rather than a single value. An inbound call rings all of them and the first to
// answer wins; see the gateway's fork handling.
package sipgw

import (
	"sort"
	"strings"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/sip"
)

const (
	// minExpiry rejects a client asking to re-register every few seconds, which
	// would turn a phone with a flaky connection into a busy loop.
	minExpiry = 60
	// maxExpiry caps a client's request. A long binding survives a NAT mapping
	// timeout and then silently fails, so the gateway prefers refreshes.
	maxExpiry = 3600
	// defaultExpiry applies when a client sends no Expires at all.
	defaultExpiry = 600
)

// Binding is one reachable client.
type Binding struct {
	// Contact is the URI the client asked to be reached at, as it wrote it.
	Contact string
	// Target is where datagrams actually go: the observed source address, not
	// the Contact host. A phone behind NAT advertises an address that is
	// unreachable from here, so trusting Contact would make inbound calls
	// silently fail.
	Target string
	// UserAgent helps an operator recognise which device this is.
	UserAgent string
	CallID    string
	// CSeq is the highest sequence seen, used to ignore a replayed REGISTER
	// arriving out of order.
	CSeq      int
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Expired reports whether the binding has lapsed.
func (binding Binding) Expired(now time.Time) bool {
	return !binding.ExpiresAt.After(now)
}

// Registrar holds the bindings for one account.
type Registrar struct {
	mu       sync.RWMutex
	bindings map[string]Binding
}

func NewRegistrar() *Registrar {
	return &Registrar{bindings: map[string]Binding{}}
}

// NormalizeExpiry clamps a requested lifetime into the supported range.
func NormalizeExpiry(requested int, present bool) int {
	if !present {
		return defaultExpiry
	}
	if requested < minExpiry {
		return minExpiry
	}
	if requested > maxExpiry {
		return maxExpiry
	}
	return requested
}

// Register records or refreshes a binding and returns the granted expiry.
//
// source is the observed remote address and becomes the delivery target. It is
// never taken from the message, because a client behind NAT cannot know its own
// public address and a hostile client could name someone else's.
func (registrar *Registrar) Register(message *sip.Message, source string, granted int) Binding {
	contact := strings.TrimSpace(message.Get("Contact"))
	key := contactKey(contact)
	cseq, _ := message.CSeq()

	registrar.mu.Lock()
	defer registrar.mu.Unlock()

	now := time.Now()
	binding := Binding{
		Contact:   contact,
		Target:    source,
		UserAgent: strings.TrimSpace(message.Get("User-Agent")),
		CallID:    message.CallID(),
		CSeq:      cseq,
		ExpiresAt: now.Add(time.Duration(granted) * time.Second),
		CreatedAt: now,
	}
	if existing, ok := registrar.bindings[key]; ok {
		// A re-registration keeps the original creation time so the panel can
		// show how long a device has been online.
		binding.CreatedAt = existing.CreatedAt
	}
	registrar.bindings[key] = binding
	return binding
}

// Unregister drops one binding, or all of them for a wildcard Contact.
func (registrar *Registrar) Unregister(message *sip.Message) {
	contact := strings.TrimSpace(message.Get("Contact"))
	registrar.mu.Lock()
	defer registrar.mu.Unlock()
	if contact == "*" || contact == "" {
		registrar.bindings = map[string]Binding{}
		return
	}
	delete(registrar.bindings, contactKey(contact))
}

// Targets returns every live binding, newest first, after pruning expired ones.
// Newest first because a device that just registered is the one most likely to
// be in the operator's hand.
func (registrar *Registrar) Targets() []Binding {
	registrar.mu.Lock()
	defer registrar.mu.Unlock()
	now := time.Now()
	for key, binding := range registrar.bindings {
		if binding.Expired(now) {
			delete(registrar.bindings, key)
		}
	}
	live := make([]Binding, 0, len(registrar.bindings))
	for _, binding := range registrar.bindings {
		live = append(live, binding)
	}
	sort.SliceStable(live, func(i, j int) bool {
		return live[i].ExpiresAt.After(live[j].ExpiresAt)
	})
	return live
}

// Registered reports whether any client is currently reachable.
func (registrar *Registrar) Registered() bool {
	return len(registrar.Targets()) > 0
}

// Clear drops every binding, used when an account is disabled or deleted.
func (registrar *Registrar) Clear() {
	registrar.mu.Lock()
	defer registrar.mu.Unlock()
	registrar.bindings = map[string]Binding{}
}

// contactKey identifies a binding. The URI inside the angle brackets is used,
// stripped of parameters, so a client that varies its display name or adds
// ;expires does not create a duplicate binding on every refresh.
func contactKey(contact string) string {
	contact = strings.TrimSpace(contact)
	if contact == "" || contact == "*" {
		return contact
	}
	if uri, err := sip.ParseURI(contact); err == nil {
		return strings.ToLower(uri.Scheme + ":" + uri.User + "@" + uri.HostPort())
	}
	return strings.ToLower(contact)
}
