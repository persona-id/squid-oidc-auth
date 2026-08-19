// Package protocol implements the line-oriented helper protocol that Squid
// speaks to external ACL and authentication helpers.
//
// Squid writes one request per line on the helper's stdin and reads one
// response per line from its stdout. When the helper is configured with
// concurrency, every line is prefixed with a channel ID that the response must
// echo back, which lets Squid keep multiple requests in flight over the single
// pipe.
package protocol

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Code is the result code that leads a helper response.
type Code string

const (
	// CodeBH reports that the helper itself failed, leaving the lookup
	// unanswered. Squid applies its configured on-error policy.
	CodeBH Code = "BH"
	// CodeERR reports a successful lookup with a negative result.
	CodeERR Code = "ERR"
	// CodeOK reports a successful lookup with a positive result.
	CodeOK Code = "OK"
)

// NoChannel is the channel ID of a request received on a helper that runs
// without concurrency, where lines carry no channel prefix.
const NoChannel = -1

// basicAuthFields is how many fields a basic authentication request carries
// without a channel prefix: the login and the credential.
const basicAuthFields = 2

var (
	// ErrChannelMismatch reports a request whose shape contradicts the helper's
	// concurrency setting. Squid always sends exactly the fields its
	// configuration implies, so this is a mismatch between --concurrent and
	// concurrency= rather than anything a client can provoke.
	ErrChannelMismatch = errors.New("request does not match the helper's concurrency setting")
	// ErrControlCharacter reports a response carrying a character that cannot
	// survive a line-oriented protocol. Quoting cannot rescue these: a newline
	// inside a value would emit a second line that Squid reads as an additional
	// response, which under concurrency lets attacker-influenced claim data
	// forge an answer to a request the helper never saw.
	ErrControlCharacter = errors.New("value contains a control character")
	// ErrEmptyRequest reports a blank request line.
	ErrEmptyRequest = errors.New("empty request line")
	// ErrInvalidKey reports a key that is not a bare token, and so cannot be
	// distinguished from the value once written.
	ErrInvalidKey = errors.New("key is empty or contains a reserved character")
)

// Pair is a key=value annotation on a response. Squid understands a fixed set
// of keys, including log, message, tag, ttl, and user.
type Pair struct {
	Key   string
	Value string
}

// Request is a single lookup Squid asked the helper to answer. Fields holds the
// values Squid sent, in order and already unescaped: for a basic authentication
// helper, the username and the password.
type Request struct {
	ChannelID int
	Fields    []string
}

// ParseRequest parses a single request line. Set concurrent to match the
// helper's Squid configuration: when true, the line is expected to start with a
// channel ID.
func ParseRequest(line string, concurrent bool) (Request, error) {
	req := Request{ChannelID: NoChannel}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return req, ErrEmptyRequest
	}

	if concurrent {
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			return req, fmt.Errorf(
				"%w: expected a channel ID first but got %q; "+
					"the helper was started with --concurrent, so squid.conf needs concurrency= on this helper",
				ErrChannelMismatch, fields[0],
			)
		}

		req.ChannelID = id
		fields = fields[1:]
	} else if len(fields) > basicAuthFields && isNumeric(fields[0]) {
		// Squid sends exactly the fields its configuration implies, and a basic
		// authentication request carries two. A third, led by a number, means
		// channel IDs are arriving that this helper is not consuming - which
		// would otherwise read the login as the credential and deny everything.
		return req, fmt.Errorf(
			"%w: got %d fields led by %q, which looks like a channel ID; "+
				"squid.conf sets concurrency= on this helper but it was started without --concurrent",
			ErrChannelMismatch, len(fields), fields[0],
		)
	}

	req.Fields = make([]string, 0, len(fields))
	for _, field := range fields {
		req.Fields = append(req.Fields, unescape(field))
	}

	return req, nil
}

// Field returns the field at i, or the empty string when the request carried
// fewer fields than expected.
func (r Request) Field(i int) string {
	if i < 0 || i >= len(r.Fields) {
		return ""
	}

	return r.Fields[i]
}

// Response is the helper's answer to a single request.
type Response struct {
	ChannelID int
	Code      Code
	Pairs     []Pair
}

// Encode renders the response as the single line Squid expects, without a
// trailing newline.
//
// It fails rather than emitting anything that would not survive the line
// protocol. Pair values carry data derived from the token being checked, so a
// caller must treat an error as a failed lookup and answer BH, never as
// something to sanitize and send anyway.
func (r Response) Encode() (string, error) {
	var b strings.Builder

	if r.ChannelID != NoChannel {
		b.WriteString(strconv.Itoa(r.ChannelID))
		b.WriteByte(' ')
	}

	b.WriteString(string(r.Code))

	for _, pair := range r.Pairs {
		if !ValidKey(pair.Key) {
			return "", fmt.Errorf("%w: %q", ErrInvalidKey, pair.Key)
		}

		if strings.ContainsFunc(pair.Value, isControl) {
			return "", fmt.Errorf("%w: key %q", ErrControlCharacter, pair.Key)
		}

		b.WriteByte(' ')
		b.WriteString(pair.Key)
		b.WriteByte('=')
		b.WriteString(quote(pair.Value))
	}

	return b.String(), nil
}

// ValidKey reports whether key is a bare token, so that a reader can find the
// "=" that separates it from its value. Callers that build keys from
// configuration should check them at load time rather than discovering the
// problem on the first request.
func ValidKey(key string) bool {
	if key == "" {
		return false
	}

	for _, r := range key {
		if r == '=' || r == '"' || r == '\\' || r == ' ' || r == '\t' || isControl(r) {
			return false
		}
	}

	return true
}

// isControl reports whether r cannot appear literally in a response line. Space
// is not a control character; quoting handles it.
func isControl(r rune) bool {
	return r < ' ' || r == 0x7f
}

// isNumeric reports whether field is entirely digits, which is what a channel
// ID looks like.
func isNumeric(field string) bool {
	if field == "" {
		return false
	}

	for _, r := range field {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// quote wraps a value in double quotes when it would otherwise break the
// key=value grammar, escaping the characters that quoting alone cannot carry.
// Callers must reject control characters first; quoting cannot represent them.
func quote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\"\\") {
		return value
	}

	var b strings.Builder

	b.WriteByte('"')

	for _, r := range value {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}

		b.WriteRune(r)
	}

	b.WriteByte('"')

	return b.String()
}

// unescape reverses the percent-encoding Squid applies to field values. A field
// that does not decode cleanly is passed through untouched, since rejecting the
// whole request would be a worse answer than an opaque one.
func unescape(field string) string {
	if !strings.ContainsRune(field, '%') {
		return field
	}

	// PathUnescape rather than QueryUnescape: Squid percent-encodes, and a
	// literal "+" in a token must not become a space.
	decoded, err := url.PathUnescape(field)
	if err != nil {
		return field
	}

	return decoded
}
