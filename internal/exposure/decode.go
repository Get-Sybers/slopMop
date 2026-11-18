package exposure

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// maxDecoded is how many bytes of a decoded value are written.
	maxDecoded = 240
	// maxField is how many bytes of one field of a decoded document are written.
	maxField = 64
	// minEncoded is the length below which a value is not tried as base64.
	minEncoded = 16
	// formBasic is the form of the credentials of HTTP basic authentication,
	// which are a username and a password in base64.
	formBasic = "basic"
	// pemBegins is how the header of a key or certificate block begins.
	pemBegins = "-----BEGIN "
)

// tokenEntry names the claims of a JSON web token that are read: those
// that say whose it is, in the order they are tried, those that say what it
// is for, those written when it is decoded, and those that are times.
type tokenEntry struct {
	Owner    []string `json:"owner"`
	Audience []string `json:"audience"`
	Shown    []string `json:"shown"`
	Times    []string `json:"times"`
}

// check accepts a table that reads no token, and one that names the claims
// of each use.
func (e tokenEntry) check() error {
	if len(e.Owner)+len(e.Audience)+len(e.Shown)+len(e.Times) == 0 {
		return nil
	}
	if len(e.Owner) == 0 || len(e.Audience) == 0 || len(e.Shown) == 0 {
		return errors.New("token needs the claims that name the owner, the audience and what is shown")
	}
	for _, name := range slices.Concat(e.Owner, e.Audience, e.Shown, e.Times) {
		if name == "" {
			return errors.New("token names an empty claim")
		}
	}
	return nil
}

// field is one member of a JSON object, in the order of the document.
type field struct {
	name  string
	value any
}

// object reads a JSON object and keeps the order of its members; ok is
// false for a text that is not one object.
func object(text []byte) ([]field, bool) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	if open, err := dec.Token(); err != nil || open != json.Delim('{') {
		return nil, false
	}
	var fields []field
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return nil, false
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		fields = append(fields, field{name: fmt.Sprint(name), value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return fields, true
}

// claims reads the claims of a JSON web token; ok is false for a value that
// is not one.
func claims(token string) ([]field, bool) {
	if !strings.HasPrefix(token, "eyJ") {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	for _, part := range parts[:2] {
		if _, ok := object(unbase64(part)); !ok {
			return nil, false
		}
	}
	return object(unbase64(parts[1]))
}

// unbase64 decodes base64 in either alphabet, padded or not; nil when the
// text is not base64.
func unbase64(text string) []byte {
	text = strings.TrimRight(text, "=")
	encoding := base64.RawStdEncoding
	if strings.ContainsAny(text, "-_") {
		encoding = base64.RawURLEncoding
	}
	decoded, err := encoding.DecodeString(text)
	if err != nil {
		return nil
	}
	return decoded
}

// claim returns the first of the named claims that is a text.
func claim(fields []field, names []string) string {
	for _, name := range names {
		for _, f := range fields {
			if text, ok := f.value.(string); ok && f.name == name && text != "" {
				return text
			}
		}
	}
	return ""
}

// held reads what an encoded secret says of itself: the claims of a JSON
// web token, bare or in base64, or the members of a document in base64.
func held(value string) ([]field, bool) {
	if fields, ok := claims(value); ok {
		return fields, true
	}
	if !strings.HasPrefix(value, "ZXlK") && !strings.HasPrefix(value, "ew") && !strings.HasPrefix(value, "ey") {
		return nil, false
	}
	text, ok := plain(value)
	if !ok {
		return nil, false
	}
	if fields, ok := claims(strings.TrimSpace(text)); ok {
		return fields, true
	}
	return object([]byte(text))
}

// tokenOwner names whose an encoded secret is, by the first member that
// says; it is empty for a value that holds no document or names no one.
func (t Table) tokenOwner(value string) string {
	if len(t.token.Owner) == 0 {
		return ""
	}
	fields, ok := held(value)
	if !ok {
		return ""
	}
	return claim(fields, t.token.Owner)
}

// audience names what a JSON web token is for: the service of the host its
// audience names, else the audience itself.
func (t Table) audience(value string) string {
	if len(t.token.Audience) == 0 {
		return ""
	}
	fields, ok := held(value)
	if !ok {
		return ""
	}
	aud := claim(fields, t.token.Audience)
	if aud == "" {
		return ""
	}
	host := aud
	if _, rest, isURL := strings.Cut(aud, "://"); isURL {
		host, _, _ = strings.Cut(rest, "/")
	}
	if name := t.hosted(strings.ToLower(host)); name != "" {
		return name
	}
	return aud
}

// Decoded writes an encoded value as a reader takes it in: the claims of a
// JSON web token, the type and fingerprint of a key block, the text that
// base64 holds. ok is false for a value that says no more decoded.
func (t Table) Decoded(value string) (string, bool) {
	if fields, ok := claims(value); ok {
		return t.written(fields, t.token.Shown), true
	}
	if strings.HasPrefix(value, pemBegins) {
		return block(value)
	}
	text, ok := plain(value)
	if !ok {
		return "", false
	}
	// What base64 holds is often a token or a document of its own.
	if fields, ok := claims(strings.TrimSpace(text)); ok {
		return t.written(fields, t.token.Shown), true
	}
	if fields, ok := object([]byte(text)); ok && len(fields) > 0 {
		return t.written(fields, nil), true
	}
	return shortened(strings.Join(strings.Fields(text), " "), maxDecoded), true
}

// plain decodes base64 that holds text; ok is false for a value that is not
// base64 or whose bytes are not text.
func plain(value string) (string, bool) {
	if len(value) < minEncoded || strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	decoded := unbase64(value)
	if len(decoded) < minEncoded/2 || !utf8.Valid(decoded) {
		return "", false
	}
	words := 0
	for _, r := range string(decoded) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
		case unicode.IsControl(r) || r == utf8.RuneError:
			return "", false
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ':
			words++
		}
	}
	// Text is mostly letters, digits and spaces; chance bytes are not.
	if words*5 < utf8.RuneCount(decoded)*3 {
		return "", false
	}
	return string(decoded), true
}

// block names a key or certificate block by its type and the SHA-256 of
// what it holds, so a key of any length is one short value.
func block(value string) (string, bool) {
	rest := strings.TrimPrefix(value, pemBegins)
	kind, body, found := strings.Cut(rest, "-----")
	if !found || kind == "" {
		return "", false
	}
	body, _, _ = strings.Cut(body, "-----END")
	der := unbase64(strings.Join(strings.Fields(strings.ReplaceAll(body, `\n`, " ")), ""))
	if len(der) == 0 {
		return kind + " (PEM)", true
	}
	sum := sha256.Sum256(der)
	return kind + " (PEM) SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), true
}

// written writes the members of a document as name=value, those named and
// in that order, or every one when none is named. A time is written as one.
func (t Table) written(fields []field, names []string) string {
	var parts []string
	said := map[string]bool{}
	// A token often says the same under two names: it is written once.
	add := func(f field) {
		if text := t.worded(f); text != "" && !said[text] {
			said[text] = true
			parts = append(parts, f.name+"="+shortened(text, maxField))
		}
	}
	for _, name := range names {
		for _, f := range fields {
			if f.name == name {
				add(f)
			}
		}
	}
	if len(parts) == 0 {
		for _, f := range fields {
			add(f)
		}
	}
	return shortened(strings.Join(parts, "; "), maxDecoded)
}

// worded writes the value of one member: a text as it stands, a time as an
// instant, a list by its items; a nested document is left out.
func (t Table) worded(f field) string {
	switch v := f.value.(type) {
	case string:
		return strings.Join(strings.Fields(v), " ")
	case json.Number:
		if seconds, err := v.Int64(); err == nil && slices.Contains(t.token.Times, f.name) {
			return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
		}
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case []any:
		items := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				items = append(items, text)
			}
		}
		return strings.Join(items, " ")
	}
	return ""
}

// shortened cuts a text to limit bytes, ending in "..." and never inside a rune.
func shortened(text string, limit int) string {
	const ellipsis = "..."
	if len(text) <= limit {
		return text
	}
	end := limit - len(ellipsis)
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end] + ellipsis
}

// basic reads the credentials of HTTP basic authentication: the username
// and the password that base64 holds with a colon between them.
func basic(value string) (account, password string, ok bool) {
	decoded := unbase64(value)
	if !utf8.Valid(decoded) {
		return "", "", false
	}
	account, password, ok = strings.Cut(string(decoded), ":")
	if !ok || account == "" || password == "" || strings.ContainsAny(account, " \t\r\n") {
		return "", "", false
	}
	return account, password, true
}
