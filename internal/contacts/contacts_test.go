package contacts

import "testing"

func TestMatchKeyIgnoresFormattingAndCountryCode(t *testing.T) {
	// A carrier may present the same subscriber in any of these forms, so all
	// must reduce to the same key.
	forms := []string{
		"+447700900123", "447700900123", "07700900123", "7700900123",
		"+44 7700 900123", "(0)7700-900123",
	}
	want := MatchKey(forms[0])
	if want == "" {
		t.Fatal("MatchKey returned empty for a valid number")
	}
	for _, form := range forms {
		if got := MatchKey(form); got != want {
			t.Fatalf("MatchKey(%q) = %q, want %q", form, got, want)
		}
	}
}

func TestShortNumbersMatchExactly(t *testing.T) {
	// Service numbers are shorter than the comparison window and must not be
	// padded or truncated into a collision.
	if MatchKey("10086") != "10086" {
		t.Fatalf("MatchKey(10086) = %q", MatchKey("10086"))
	}
	if SameNumber("10086", "110086") {
		t.Fatal("a longer number must not match a short code by suffix")
	}
	if !SameNumber("10086", "10086") {
		t.Fatal("identical short codes must match")
	}
}

func TestDifferentSubscribersDoNotMatch(t *testing.T) {
	if SameNumber("+447700900123", "+447700900124") {
		t.Fatal("numbers differing in the last digit must not match")
	}
	if SameNumber("", "+447700900123") {
		t.Fatal("an empty number must never match")
	}
	if SameNumber("abc", "def") {
		t.Fatal("numbers with no digits must never match")
	}
}

func TestBookLookupAndNameFallback(t *testing.T) {
	book := NewBook([]Contact{
		{Number: "+447700900123", Name: "Alice"},
		{Number: "10086", Name: "Carrier"},
		{Number: "  ", Name: "Ignored"},
		{Number: "+447700900999", Name: ""},
	})
	// A national-format inbound number must still find the E.164 contact.
	if name := book.Name("07700900123"); name != "Alice" {
		t.Fatalf("Name(07700900123) = %q, want Alice", name)
	}
	if name := book.Name("10086"); name != "Carrier" {
		t.Fatalf("Name(10086) = %q, want Carrier", name)
	}
	// Unknown numbers fall back to the number itself so notifications are never
	// blank.
	if name := book.Name("+447700900555"); name != "+447700900555" {
		t.Fatalf("Name(unknown) = %q", name)
	}
	if _, ok := book.Lookup("+447700900999"); ok {
		t.Fatal("a contact with no name must be dropped")
	}
	if len(book.List()) != 2 {
		t.Fatalf("List() = %d contacts, want 2", len(book.List()))
	}
}

func TestNilBookIsUsable(t *testing.T) {
	// The engine may run before any contact is configured.
	var book *Book
	if _, ok := book.Lookup("+447700900123"); ok {
		t.Fatal("nil book must not match")
	}
	if name := book.Name(" +447700900123 "); name != "+447700900123" {
		t.Fatalf("Name on nil book = %q", name)
	}
	if len(book.List()) != 0 {
		t.Fatal("nil book must list nothing")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(Contact{Number: "+447700900123", Name: "Alice"}); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
	for name, contact := range map[string]Contact{
		"no name":     {Number: "+447700900123"},
		"no digits":   {Number: "abc", Name: "Alice"},
		"long name":   {Number: "+447700900123", Name: string(make([]byte, 101))},
		"long number": {Number: string(make([]byte, 41)), Name: "Alice"},
		"long note":   {Number: "+447700900123", Name: "Alice", Note: string(make([]byte, 201))},
	} {
		if err := Validate(contact); err == nil {
			t.Fatalf("%s: Validate() must fail", name)
		}
	}
}
