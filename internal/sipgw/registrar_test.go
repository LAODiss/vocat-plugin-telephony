package sipgw

import (
	"testing"
	"time"

	"vocat-plugin-telephony/internal/sip"
)

func registerMessage(t *testing.T, contact, callID string, cseq int, expires string) *sip.Message {
	t.Helper()
	raw := "REGISTER sip:vocat.local SIP/2.0\r\n" +
		"From: <sip:alice@vocat.local>;tag=t1\r\n" +
		"To: <sip:alice@vocat.local>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: " + itoa(cseq) + " REGISTER\r\n" +
		"Contact: " + contact + "\r\n" +
		"User-Agent: Linphone/5.2\r\n"
	if expires != "" {
		raw += "Expires: " + expires + "\r\n"
	}
	message, err := sip.Parse([]byte(raw + "\r\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return message
}

func TestRegisterUsesObservedSourceNotContactHost(t *testing.T) {
	// A phone behind NAT advertises an address unreachable from here. Trusting
	// Contact would make every inbound call silently fail.
	registrar := NewRegistrar()
	message := registerMessage(t, "<sip:alice@192.168.1.50:5060>", "c1", 1, "600")
	binding := registrar.Register(message, "203.0.113.9:41234", 600)

	if binding.Target != "203.0.113.9:41234" {
		t.Fatalf("Target = %q, want the observed source", binding.Target)
	}
	if binding.Contact != "<sip:alice@192.168.1.50:5060>" {
		t.Fatalf("Contact = %q, want the client's own value preserved", binding.Contact)
	}
	if binding.UserAgent != "Linphone/5.2" {
		t.Fatalf("UserAgent = %q", binding.UserAgent)
	}
	targets := registrar.Targets()
	if len(targets) != 1 || targets[0].Target != "203.0.113.9:41234" {
		t.Fatalf("Targets() = %+v", targets)
	}
}

func TestMultipleDevicesRegisterConcurrently(t *testing.T) {
	// A phone and a desktop client on one account is the common case; both must
	// be reachable so an inbound call can ring each.
	registrar := NewRegistrar()
	registrar.Register(registerMessage(t, "<sip:alice@192.168.1.50:5060>", "phone", 1, "600"),
		"192.168.1.50:5060", 600)
	registrar.Register(registerMessage(t, "<sip:alice@192.168.1.77:5062>", "desktop", 1, "600"),
		"192.168.1.77:5062", 600)

	if got := len(registrar.Targets()); got != 2 {
		t.Fatalf("Targets() = %d bindings, want 2", got)
	}
}

func TestRefreshDoesNotDuplicateABinding(t *testing.T) {
	// A client refreshes every few minutes, often varying the display name or
	// adding ;expires. Each refresh must update the binding, not add one.
	registrar := NewRegistrar()
	registrar.Register(registerMessage(t, "<sip:alice@192.168.1.50:5060>", "c1", 1, "600"),
		"192.168.1.50:5060", 600)
	first := registrar.Targets()[0]

	registrar.Register(registerMessage(t,
		`"Alice" <sip:alice@192.168.1.50:5060>;expires=600`, "c1", 2, "600"),
		"192.168.1.50:5060", 600)

	targets := registrar.Targets()
	if len(targets) != 1 {
		t.Fatalf("refresh created %d bindings, want 1", len(targets))
	}
	// The creation time is kept so the panel can show how long a device has been
	// online across refreshes.
	if !targets[0].CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("refresh reset the creation time")
	}
	if targets[0].CSeq != 2 {
		t.Fatalf("CSeq = %d, want the refreshed value", targets[0].CSeq)
	}
}

func TestUnregisterDropsOneOrAll(t *testing.T) {
	registrar := NewRegistrar()
	registrar.Register(registerMessage(t, "<sip:alice@1.1.1.1:5060>", "a", 1, "600"), "1.1.1.1:5060", 600)
	registrar.Register(registerMessage(t, "<sip:alice@2.2.2.2:5060>", "b", 1, "600"), "2.2.2.2:5060", 600)

	registrar.Unregister(registerMessage(t, "<sip:alice@1.1.1.1:5060>", "a", 2, "0"))
	targets := registrar.Targets()
	if len(targets) != 1 || targets[0].Target != "2.2.2.2:5060" {
		t.Fatalf("targeted unregister removed the wrong binding: %+v", targets)
	}

	// A wildcard Contact clears everything, which is how a client signs out.
	registrar.Unregister(registerMessage(t, "*", "b", 3, "0"))
	if registrar.Registered() {
		t.Fatal("wildcard unregister left bindings behind")
	}
}

func TestExpiredBindingsArePruned(t *testing.T) {
	registrar := NewRegistrar()
	// Granting zero seconds makes the binding lapse immediately.
	registrar.Register(registerMessage(t, "<sip:alice@1.1.1.1:5060>", "a", 1, "600"), "1.1.1.1:5060", 0)
	if registrar.Registered() {
		t.Fatal("an expired binding must not count as registered")
	}
	if got := len(registrar.Targets()); got != 0 {
		t.Fatalf("Targets() = %d, want 0 after pruning", got)
	}
}

func TestBindingExpired(t *testing.T) {
	now := time.Now()
	live := Binding{ExpiresAt: now.Add(time.Minute)}
	if live.Expired(now) {
		t.Fatal("a future expiry must not read as expired")
	}
	// Exactly at the deadline counts as expired, so a lapsed binding is never
	// used for one more call.
	boundary := Binding{ExpiresAt: now}
	if !boundary.Expired(now) {
		t.Fatal("a binding at its deadline must read as expired")
	}
}

func TestNormalizeExpiryClampsClientRequests(t *testing.T) {
	// Too short turns a flaky phone into a busy loop; too long outlives the NAT
	// mapping and then fails silently.
	if got := NormalizeExpiry(5, true); got != minExpiry {
		t.Fatalf("NormalizeExpiry(5) = %d, want %d", got, minExpiry)
	}
	if got := NormalizeExpiry(99999, true); got != maxExpiry {
		t.Fatalf("NormalizeExpiry(99999) = %d, want %d", got, maxExpiry)
	}
	if got := NormalizeExpiry(600, true); got != 600 {
		t.Fatalf("NormalizeExpiry(600) = %d, want it unchanged", got)
	}
	// A client that sends no Expires at all gets the default rather than zero,
	// which would read as an unregister.
	if got := NormalizeExpiry(0, false); got != defaultExpiry {
		t.Fatalf("NormalizeExpiry(absent) = %d, want %d", got, defaultExpiry)
	}
}

func TestTargetsAreNewestFirst(t *testing.T) {
	// The device that registered most recently is the one most likely to be in
	// the operator's hand.
	registrar := NewRegistrar()
	registrar.Register(registerMessage(t, "<sip:alice@1.1.1.1:5060>", "a", 1, "600"), "1.1.1.1:5060", 300)
	registrar.Register(registerMessage(t, "<sip:alice@2.2.2.2:5060>", "b", 1, "600"), "2.2.2.2:5060", 900)

	targets := registrar.Targets()
	if len(targets) != 2 {
		t.Fatalf("Targets() = %d", len(targets))
	}
	if targets[0].Target != "2.2.2.2:5060" {
		t.Fatalf("Targets()[0] = %q, want the longest-lived binding first", targets[0].Target)
	}
}

func TestClearRemovesEverything(t *testing.T) {
	registrar := NewRegistrar()
	registrar.Register(registerMessage(t, "<sip:alice@1.1.1.1:5060>", "a", 1, "600"), "1.1.1.1:5060", 600)
	registrar.Clear()
	if registrar.Registered() {
		t.Fatal("Clear() left bindings behind")
	}
}

func TestContactKeyIgnoresDisplayNameAndParameters(t *testing.T) {
	base := contactKey("<sip:alice@192.168.1.50:5060>")
	for _, variant := range []string{
		`"Alice B" <sip:alice@192.168.1.50:5060>`,
		"<sip:alice@192.168.1.50:5060>;expires=600",
		"<SIP:Alice@192.168.1.50:5060>",
		"<sip:alice@192.168.1.50:5060;transport=udp>",
	} {
		if got := contactKey(variant); got != base {
			t.Fatalf("contactKey(%q) = %q, want %q", variant, got, base)
		}
	}
	// A different port is a different device.
	if contactKey("<sip:alice@192.168.1.50:5062>") == base {
		t.Fatal("contactKey collapsed two distinct ports")
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
