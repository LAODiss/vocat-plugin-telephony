// Package sip parses and builds the subset of SIP a softphone gateway needs.
//
// This is a deliberate subset, not a general SIP stack. It handles what
// Linphone and comparable clients actually send when registering and placing a
// call: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS and their responses. It
// does not implement transactions, forking, or a transaction user layer —
// internal/sipgw drives the state machine on top of these primitives.
//
// Header handling is case-insensitive and understands the compact forms
// (f/t/i/m/v/c/l/s/k) because clients use them freely and a parser that misses
// "f:" would silently drop the From header.
package sip

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxMessageBytes bounds one datagram. RFC 3261 recommends switching to TCP
// past the MTU; a UDP-only gateway simply refuses anything larger rather than
// truncating a message into something that parses but means the wrong thing.
const MaxMessageBytes = 8192

// Message is a parsed SIP request or response.
type Message struct {
	// IsResponse distinguishes the two forms. A request has Method and URI; a
	// response has StatusCode and Reason.
	IsResponse bool

	Method string
	URI    string

	StatusCode int
	Reason     string

	// Headers preserves insertion order and original names for round-tripping,
	// while lookups go through the canonical index.
	Headers []Header
	Body    []byte
}

// Header is one header line.
type Header struct {
	Name  string
	Value string
}

// compactNames maps the single-letter forms to their canonical spelling. A
// client may use either at any time, sometimes mixing them in one message.
var compactNames = map[string]string{
	"f": "from",
	"t": "to",
	"i": "call-id",
	"m": "contact",
	"v": "via",
	"c": "content-type",
	"l": "content-length",
	"s": "subject",
	"k": "supported",
	"e": "content-encoding",
	"y": "identity",
	"o": "event",
	"r": "refer-to",
	"b": "referred-by",
	"a": "accept-contact",
	"u": "allow-events",
	"j": "reject-contact",
	"d": "request-disposition",
	"x": "session-expires",
}

// canonical lowercases a header name and expands the compact form.
func canonical(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if expanded, ok := compactNames[lower]; ok {
		return expanded
	}
	return lower
}

// Get returns the first value of a header, or "".
func (message *Message) Get(name string) string {
	want := canonical(name)
	for _, header := range message.Headers {
		if canonical(header.Name) == want {
			return header.Value
		}
	}
	return ""
}

// All returns every value of a header, in order. Via and Record-Route must
// preserve order because routing depends on it.
func (message *Message) All(name string) []string {
	want := canonical(name)
	var values []string
	for _, header := range message.Headers {
		if canonical(header.Name) == want {
			values = append(values, header.Value)
		}
	}
	return values
}

// Set replaces every occurrence of a header, or appends it when absent.
func (message *Message) Set(name, value string) {
	want := canonical(name)
	replaced := false
	filtered := message.Headers[:0]
	for _, header := range message.Headers {
		if canonical(header.Name) != want {
			filtered = append(filtered, header)
			continue
		}
		if !replaced {
			filtered = append(filtered, Header{Name: name, Value: value})
			replaced = true
		}
	}
	message.Headers = filtered
	if !replaced {
		message.Headers = append(message.Headers, Header{Name: name, Value: value})
	}
}

// Add appends a header without removing existing ones.
func (message *Message) Add(name, value string) {
	message.Headers = append(message.Headers, Header{Name: name, Value: value})
}

// Remove deletes every occurrence of a header.
func (message *Message) Remove(name string) {
	want := canonical(name)
	filtered := message.Headers[:0]
	for _, header := range message.Headers {
		if canonical(header.Name) != want {
			filtered = append(filtered, header)
		}
	}
	message.Headers = filtered
}

// CallID returns the dialog identifier.
func (message *Message) CallID() string {
	return strings.TrimSpace(message.Get("Call-ID"))
}

// CSeq returns the sequence number and method from the CSeq header.
func (message *Message) CSeq() (int, string) {
	fields := strings.Fields(message.Get("CSeq"))
	if len(fields) == 0 {
		return 0, ""
	}
	number, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, ""
	}
	method := ""
	if len(fields) > 1 {
		method = strings.ToUpper(fields[1])
	}
	return number, method
}

// Parse decodes one SIP message. The body is taken from Content-Length when
// present, because a UDP datagram can carry trailing padding.
func Parse(raw []byte) (*Message, error) {
	if len(raw) == 0 {
		return nil, errors.New("sip: empty message")
	}
	if len(raw) > MaxMessageBytes {
		return nil, fmt.Errorf("sip: message exceeds %d bytes", MaxMessageBytes)
	}
	text := string(raw)
	// Tolerate bare LF: some clients and most test tools omit the CR.
	headerEnd := strings.Index(text, "\r\n\r\n")
	separator := 4
	if headerEnd < 0 {
		headerEnd = strings.Index(text, "\n\n")
		separator = 2
	}
	head := text
	body := ""
	if headerEnd >= 0 {
		head = text[:headerEnd]
		body = text[headerEnd+separator:]
	}

	lines := unfold(head)
	if len(lines) == 0 {
		return nil, errors.New("sip: message has no start line")
	}

	message := &Message{}
	if err := parseStartLine(lines[0], message); err != nil {
		return nil, err
	}
	for _, line := range lines[1:] {
		colon := strings.Index(line, ":")
		if colon <= 0 {
			// A malformed header line is skipped rather than failing the whole
			// message; clients occasionally emit stray lines.
			continue
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if name == "" {
			continue
		}
		message.Headers = append(message.Headers, Header{Name: name, Value: value})
	}

	// Content-Length is authoritative when present and sane, so trailing bytes
	// in a datagram cannot leak into the body.
	if raw := message.Get("Content-Length"); raw != "" {
		if length, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && length >= 0 {
			if length <= len(body) {
				body = body[:length]
			}
		}
	}
	if body != "" {
		message.Body = []byte(body)
	}
	return message, nil
}

// unfold splits header lines, joining continuation lines that begin with
// whitespace as RFC 3261 requires.
func unfold(head string) []string {
	rawLines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	var lines []string
	for _, line := range rawLines {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += " " + strings.TrimSpace(line)
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func parseStartLine(line string, message *Message) error {
	fields := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(fields) < 2 {
		return fmt.Errorf("sip: malformed start line %q", line)
	}
	if strings.HasPrefix(strings.ToUpper(fields[0]), "SIP/") {
		status, err := strconv.Atoi(fields[1])
		if err != nil || status < 100 || status > 699 {
			return fmt.Errorf("sip: malformed status code %q", fields[1])
		}
		message.IsResponse = true
		message.StatusCode = status
		if len(fields) > 2 {
			message.Reason = fields[2]
		}
		return nil
	}
	if len(fields) < 3 {
		return fmt.Errorf("sip: malformed request line %q", line)
	}
	message.Method = strings.ToUpper(fields[0])
	message.URI = fields[1]
	return nil
}

// Encode serialises the message. Content-Length is always rewritten to match
// the body, because a stale value is a common source of hangs.
func (message *Message) Encode() []byte {
	var builder strings.Builder
	if message.IsResponse {
		reason := message.Reason
		if reason == "" {
			reason = ReasonPhrase(message.StatusCode)
		}
		fmt.Fprintf(&builder, "SIP/2.0 %d %s\r\n", message.StatusCode, reason)
	} else {
		fmt.Fprintf(&builder, "%s %s SIP/2.0\r\n", message.Method, message.URI)
	}
	for _, header := range message.Headers {
		if canonical(header.Name) == "content-length" {
			continue
		}
		fmt.Fprintf(&builder, "%s: %s\r\n", header.Name, header.Value)
	}
	fmt.Fprintf(&builder, "Content-Length: %d\r\n\r\n", len(message.Body))
	out := append([]byte(builder.String()), message.Body...)
	return out
}

// ReasonPhrase returns the standard reason for a status code. Unknown codes get
// a generic class phrase rather than an empty string.
func ReasonPhrase(status int) string {
	switch status {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 415:
		return "Unsupported Media Type"
	case 420:
		return "Bad Extension"
	case 423:
		return "Interval Too Brief"
	case 480:
		return "Temporarily Unavailable"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Time-out"
	case 603:
		return "Decline"
	}
	switch {
	case status < 200:
		return "Provisional"
	case status < 300:
		return "Success"
	case status < 400:
		return "Redirection"
	case status < 500:
		return "Client Error"
	case status < 600:
		return "Server Error"
	default:
		return "Global Failure"
	}
}

// URI is a parsed SIP URI. Only the parts a gateway acts on are kept.
type URI struct {
	Scheme string
	User   string
	Host   string
	Port   int
	// Transport is the transport parameter, lowercased. Empty means unspecified.
	Transport string
}

// HostPort renders host:port, omitting the port when unset.
func (uri URI) HostPort() string {
	if uri.Port == 0 {
		return uri.Host
	}
	return uri.Host + ":" + strconv.Itoa(uri.Port)
}

// String renders the URI in its canonical form.
func (uri URI) String() string {
	scheme := uri.Scheme
	if scheme == "" {
		scheme = "sip"
	}
	out := scheme + ":"
	if uri.User != "" {
		out += uri.User + "@"
	}
	out += uri.HostPort()
	if uri.Transport != "" {
		out += ";transport=" + uri.Transport
	}
	return out
}

// ParseURI decodes a SIP URI, with or without angle brackets and display name.
func ParseURI(value string) (URI, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return URI{}, errors.New("sip: empty URI")
	}
	// A display name may contain a quoted colon, so strip the angle-bracket form
	// before looking for the scheme.
	if start := strings.Index(value, "<"); start >= 0 {
		end := strings.Index(value[start:], ">")
		if end <= 0 {
			return URI{}, fmt.Errorf("sip: unterminated URI in %q", value)
		}
		value = value[start+1 : start+end]
	} else if index := strings.Index(value, ";"); index >= 0 {
		// Without brackets, parameters after the URI belong to the header, not
		// the URI — except transport, which callers rely on.
		head, params := value[:index], value[index:]
		if strings.Contains(strings.ToLower(params), "transport=") {
			value = head + extractTransportParam(params)
		} else {
			value = head
		}
	}

	uri := URI{}
	if colon := strings.Index(value, ":"); colon > 0 {
		uri.Scheme = strings.ToLower(value[:colon])
		value = value[colon+1:]
	}
	switch uri.Scheme {
	case "sip", "sips", "tel":
	case "":
		uri.Scheme = "sip"
	default:
		return URI{}, fmt.Errorf("sip: unsupported URI scheme %q", uri.Scheme)
	}

	// Split parameters off the host part.
	if index := strings.Index(value, ";"); index >= 0 {
		params := value[index:]
		value = value[:index]
		for _, param := range strings.Split(strings.TrimPrefix(params, ";"), ";") {
			key, val, _ := strings.Cut(param, "=")
			if strings.EqualFold(strings.TrimSpace(key), "transport") {
				uri.Transport = strings.ToLower(strings.TrimSpace(val))
			}
		}
	}
	if index := strings.Index(value, "?"); index >= 0 {
		value = value[:index]
	}

	if at := strings.LastIndex(value, "@"); at >= 0 {
		uri.User = value[:at]
		value = value[at+1:]
		// Strip a password; a gateway must never propagate it.
		if colon := strings.Index(uri.User, ":"); colon >= 0 {
			uri.User = uri.User[:colon]
		}
	}
	host := value
	// An IPv6 reference is bracketed, so the port colon is the one after "]".
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			uri.Host = host[1:end]
			rest := host[end+1:]
			if strings.HasPrefix(rest, ":") {
				port, err := strconv.Atoi(rest[1:])
				if err != nil || port < 1 || port > 65535 {
					return URI{}, fmt.Errorf("sip: bad port in %q", value)
				}
				uri.Port = port
			}
			return uri, nil
		}
		return URI{}, fmt.Errorf("sip: unterminated IPv6 host in %q", value)
	}
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		port, err := strconv.Atoi(host[colon+1:])
		if err != nil || port < 1 || port > 65535 {
			return URI{}, fmt.Errorf("sip: bad port in %q", value)
		}
		uri.Port = port
		host = host[:colon]
	}
	if host == "" {
		return URI{}, fmt.Errorf("sip: URI has no host: %q", value)
	}
	uri.Host = host
	return uri, nil
}

func extractTransportParam(params string) string {
	for _, param := range strings.Split(strings.TrimPrefix(params, ";"), ";") {
		key, value, _ := strings.Cut(param, "=")
		if strings.EqualFold(strings.TrimSpace(key), "transport") {
			return ";transport=" + strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

// Tag returns a header's tag parameter, used to identify a dialog side.
func Tag(header string) string {
	return Param(header, "tag")
}

// Param returns a named parameter from a header value.
func Param(header, name string) string {
	lower := strings.ToLower(header)
	needle := ";" + strings.ToLower(name) + "="
	index := strings.Index(lower, needle)
	if index < 0 {
		return ""
	}
	value := header[index+len(needle):]
	if end := strings.IndexAny(value, ";,> \t"); end >= 0 {
		value = value[:end]
	}
	return strings.Trim(value, `"`)
}

// Expires reads the registration lifetime, preferring the Expires header and
// falling back to the Contact expires parameter as clients do.
func Expires(message *Message) (int, bool) {
	if raw := strings.TrimSpace(message.Get("Expires")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
			return value, true
		}
	}
	if contact := message.Get("Contact"); contact != "" {
		if raw := Param(contact, "expires"); raw != "" {
			if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
				return value, true
			}
		}
	}
	return 0, false
}

// IsUnregister reports whether a REGISTER asks to drop its bindings: either
// Expires: 0, or a wildcard Contact.
func IsUnregister(message *Message) bool {
	if expires, ok := Expires(message); ok && expires == 0 {
		return true
	}
	return strings.TrimSpace(message.Get("Contact")) == "*"
}
