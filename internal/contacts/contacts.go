// Package contacts maps phone numbers to names.
//
// Matching is deliberately conservative. A number arrives from IMS in whatever
// form the network chose — sometimes E.164, sometimes national, sometimes with
// a trunk prefix — so exact string equality would miss most matches. The
// approach here is to compare the last N significant digits, which catches
// +447700900123 / 07700900123 / 7700900123 without the false positives that
// substring matching produces.
package contacts

import (
	"errors"
	"sort"
	"strings"
)

// significantDigits is how many trailing digits must agree for a match.
// Nine is long enough that two different subscribers colliding is unlikely, and
// short enough to survive a missing country code and trunk prefix.
const significantDigits = 9

// Contact is one entry in the address book.
type Contact struct {
	Number string `json:"number"`
	Name   string `json:"name"`
	Note   string `json:"note,omitempty"`
}

// Book is an immutable lookup built from a contact list.
type Book struct {
	contacts []Contact
	byKey    map[string]Contact
}

// NewBook indexes contacts for lookup. Later entries win on key collision, so
// the caller's ordering decides precedence.
func NewBook(contacts []Contact) *Book {
	book := &Book{
		contacts: make([]Contact, 0, len(contacts)),
		byKey:    make(map[string]Contact, len(contacts)),
	}
	for _, contact := range contacts {
		contact.Number = strings.TrimSpace(contact.Number)
		contact.Name = strings.TrimSpace(contact.Name)
		if contact.Number == "" || contact.Name == "" {
			continue
		}
		book.contacts = append(book.contacts, contact)
		if key := MatchKey(contact.Number); key != "" {
			book.byKey[key] = contact
		}
	}
	return book
}

// Lookup returns the contact for a number, if any.
func (book *Book) Lookup(number string) (Contact, bool) {
	if book == nil {
		return Contact{}, false
	}
	key := MatchKey(number)
	if key == "" {
		return Contact{}, false
	}
	contact, ok := book.byKey[key]
	return contact, ok
}

// Name returns the contact name, or the number itself when unknown. This is
// what notification templates and the UI should display.
func (book *Book) Name(number string) string {
	if contact, ok := book.Lookup(number); ok {
		return contact.Name
	}
	return strings.TrimSpace(number)
}

// List returns the contacts sorted by name for display.
func (book *Book) List() []Contact {
	if book == nil {
		return []Contact{}
	}
	sorted := append([]Contact(nil), book.contacts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

// Digits strips every non-digit character. A leading + is dropped along with
// everything else, because the country code is recovered by suffix comparison
// rather than by parsing.
func Digits(number string) string {
	var builder strings.Builder
	for _, character := range number {
		if character >= '0' && character <= '9' {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

// MatchKey reduces a number to its comparable tail. Numbers shorter than the
// window are used whole, so short codes and service numbers still match
// exactly.
func MatchKey(number string) string {
	digits := Digits(number)
	if digits == "" {
		return ""
	}
	if len(digits) <= significantDigits {
		return digits
	}
	return digits[len(digits)-significantDigits:]
}

// SameNumber reports whether two numbers refer to the same subscriber.
func SameNumber(left, right string) bool {
	leftKey, rightKey := MatchKey(left), MatchKey(right)
	return leftKey != "" && leftKey == rightKey
}

// Validate checks a contact before storing it.
func Validate(contact Contact) error {
	if strings.TrimSpace(contact.Name) == "" {
		return errors.New("contact name is required")
	}
	if len(contact.Name) > 100 {
		return errors.New("contact name must be 100 characters or fewer")
	}
	if Digits(contact.Number) == "" {
		return errors.New("contact number must contain at least one digit")
	}
	if len(contact.Number) > 40 {
		return errors.New("contact number must be 40 characters or fewer")
	}
	if len(contact.Note) > 200 {
		return errors.New("contact note must be 200 characters or fewer")
	}
	return nil
}
