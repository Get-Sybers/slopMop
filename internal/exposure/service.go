package exposure

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

type serviceEntry struct {
	Name string `json:"name"`
	// Group gives what is of the service a group of its own in the report.
	Group bool `json:"group,omitempty"`
	// Words are words of a field name that say its value is of the service.
	Words []string `json:"words,omitempty"`
	// Values are expressions that a value of the service matches.
	Values []valueEntry `json:"values,omitempty"`
	// Issuers are the hosts that issue the tokens of the service.
	Issuers []string `json:"issuers,omitempty"`
}

// valueEntry is an expression and the kinds it is tried on; every kind when none is named.
type valueEntry struct {
	Kinds   []string `json:"kinds,omitempty"`
	Pattern string   `json:"pattern"`
}

// Service is what a value gives access to: a cloud, or the provider of a key.
type Service struct {
	Name string
	// Group says the report lists what is of the service in a group of its own.
	Group bool
}

type service struct {
	Service
	values  []serviceValue
	issuers []string
}

type serviceValue struct {
	kinds []int
	rx    *regexp.Regexp
}

// formPublicKey is the form of a public key of SSH, which is named by its fingerprint.
const formPublicKey = "public key"

func (t *Table) addServices(entries []serviceEntry) error {
	t.words = map[string]string{}
	names := map[string]bool{}
	for _, e := range entries {
		if e.Name == "" || names[e.Name] {
			return fmt.Errorf("the service %q is named twice or has no name", e.Name)
		}
		names[e.Name] = true
		s := service{Service: Service{Name: e.Name, Group: e.Group}, issuers: e.Issuers}
		for _, word := range e.Words {
			if _, taken := t.words[word]; taken || word == "" || word != normalise(word) {
				return fmt.Errorf("%s: the word %q is of two services or is not lower-case letters and digits", e.Name, word)
			}
			t.words[word] = e.Name
		}
		for _, host := range e.Issuers {
			if host == "" || host != strings.ToLower(host) {
				return fmt.Errorf("%s: the issuer %q is empty or not lower case", e.Name, host)
			}
		}
		for _, v := range e.Values {
			rx, err := regexp.Compile(v.Pattern)
			if err != nil {
				return fmt.Errorf("%s: %w", e.Name, err)
			}
			value := serviceValue{rx: rx}
			for _, name := range v.Kinds {
				i := slices.IndexFunc(t.kinds, func(k compiledKind) bool { return k.Name == name })
				if i < 0 {
					return fmt.Errorf("%s names the kind %q, which the table lacks", e.Name, name)
				}
				value.kinds = append(value.kinds, i)
			}
			s.values = append(s.values, value)
		}
		t.services = append(t.services, s)
	}
	for _, p := range t.patterns {
		if p.service != "" && !names[p.service] {
			return fmt.Errorf("a pattern names the service %q, which the table lacks", p.service)
		}
	}
	// One expression for each kind says whether a value is of any service at
	// all, so a value of none, as most are, is tried once and not for each.
	t.ofAny = make([]*regexp.Regexp, len(t.kinds))
	for kind := range t.kinds {
		var all []string
		for i, e := range entries {
			for n, v := range e.Values {
				if applies := t.services[i].values[n].kinds; len(applies) == 0 || slices.Contains(applies, kind) {
					all = append(all, "(?:"+v.Pattern+")")
				}
			}
		}
		if len(all) > 0 {
			t.ofAny[kind] = regexp.MustCompile(strings.Join(all, "|"))
		}
	}
	return nil
}

// Services lists the services, in the order of the data file.
func (t Table) Services() []Service {
	out := make([]Service, len(t.services))
	for i, s := range t.services {
		out[i] = s.Service
	}
	return out
}

// serviceOf names the service of a value: the one its rule gives, else the
// one the value itself shows, else the one a word of its field name names.
func (t Table) serviceOf(kind int, value, given, key string) string {
	if given != "" {
		return given
	}
	if some := t.ofAny[kind]; some != nil && some.MatchString(value) {
		for _, s := range t.services {
			for _, v := range s.values {
				if (len(v.kinds) == 0 || slices.Contains(v.kinds, kind)) && v.rx.MatchString(value) {
					return s.Name
				}
			}
		}
	}
	if name := t.issuer(value); name != "" {
		return name
	}
	if key == "" {
		return ""
	}
	for _, word := range words(key) {
		if name, ok := t.words[word]; ok {
			return name
		}
	}
	return ""
}

// issuer names the service that issued a JSON web token: the one whose host
// the claims of the token name.
func (t Table) issuer(token string) string {
	if !strings.HasPrefix(token, "eyJ") {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return ""
	}
	claims, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	lower := strings.ToLower(string(claims))
	for _, s := range t.services {
		if slices.ContainsFunc(s.issuers, func(host string) bool { return strings.Contains(lower, host) }) {
			return s.Name
		}
	}
	return ""
}

// words cuts a field name into its words, in lower case: at what is no
// letter and no digit, and where a capital follows a small letter.
func words(key string) []string {
	var out []string
	var word []rune
	end := func() {
		if len(word) > 0 {
			out = append(out, strings.ToLower(string(word)))
			word = word[:0]
		}
	}
	small := false
	for _, r := range key {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			end()
		case unicode.IsUpper(r) && small:
			end()
			word = append(word, r)
		default:
			word = append(word, r)
		}
		small = unicode.IsLower(r)
	}
	end()
	return out
}

// fingerprint names a public key of SSH as ssh-keygen does: its type and
// the SHA-256 of the key, so a key of any length is one short value.
func fingerprint(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return key
	}
	blob, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(fields[1], "="))
	if err != nil {
		return key
	}
	sum := sha256.Sum256(blob)
	return fields[0] + " SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
