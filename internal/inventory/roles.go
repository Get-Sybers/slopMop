package inventory

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/get-sybers/slopmop/internal/evidence"
)

//go:embed roles.json
var rolesJSON []byte

type RoleSpec struct {
	Name       evidence.Role `json:"name"`
	Summary    string        `json:"summary"`
	Extensions []string      `json:"extensions"`
	Shebangs   []string      `json:"shebangs"`
}

// LoadRoles returns the roles in the order they are tried.
func LoadRoles() ([]RoleSpec, error) {
	return decodeRoles(rolesJSON)
}

func decodeRoles(data []byte) ([]RoleSpec, error) {
	var doc struct {
		Roles []RoleSpec `json:"roles"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("roles.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("roles.json: data after the document")
	}
	if err := checkRoles(doc.Roles); err != nil {
		return nil, fmt.Errorf("roles.json: %w", err)
	}
	return doc.Roles, nil
}

func checkRoles(roles []RoleSpec) error {
	want := []evidence.Role{evidence.Script, evidence.Output, evidence.Other}
	if len(roles) != len(want) {
		return fmt.Errorf("%d roles, want %d", len(roles), len(want))
	}
	owner := map[string]evidence.Role{}
	for i, r := range roles {
		if r.Name != want[i] {
			return fmt.Errorf("role %d is %q, want %q", i+1, r.Name, want[i])
		}
		if strings.TrimSpace(r.Summary) == "" {
			return fmt.Errorf("role %q has no summary", r.Name)
		}
		// The last role catches every file the others leave.
		if r.Name == evidence.Other && len(r.Extensions)+len(r.Shebangs) > 0 {
			return fmt.Errorf("role %q takes no extensions or shebangs", r.Name)
		}
		for _, ext := range r.Extensions {
			if len(ext) < 2 || ext[0] != '.' || ext != strings.ToLower(ext) {
				return fmt.Errorf("role %q: extension %q is not a lower-case dot extension", r.Name, ext)
			}
			if prev, taken := owner[ext]; taken {
				return fmt.Errorf("extension %q is in %q and %q", ext, prev, r.Name)
			}
			owner[ext] = r.Name
		}
		for _, pattern := range r.Shebangs {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("role %q: shebang %q: %w", r.Name, pattern, err)
			}
		}
	}
	return nil
}

type classifier struct {
	byExtension map[string]evidence.Role
	shebangs    map[evidence.Role][]*regexp.Regexp
}

func newClassifier(roles []RoleSpec) classifier {
	c := classifier{
		byExtension: map[string]evidence.Role{},
		shebangs:    map[evidence.Role][]*regexp.Regexp{},
	}
	for _, r := range roles {
		for _, ext := range r.Extensions {
			c.byExtension[ext] = r.Name
		}
		for _, pattern := range r.Shebangs {
			c.shebangs[r.Name] = append(c.shebangs[r.Name], regexp.MustCompile(pattern))
		}
	}
	return c
}

func (c classifier) byName(name string) evidence.Role {
	if role, ok := c.byExtension[strings.ToLower(extension(name))]; ok {
		return role
	}
	return evidence.Other
}

// byText promotes a file no extension claims when its text opens with a shebang.
func (c classifier) byText(text string) evidence.Role {
	for _, role := range []evidence.Role{evidence.Script, evidence.Output} {
		for _, rx := range c.shebangs[role] {
			if rx.MatchString(text) {
				return role
			}
		}
	}
	return evidence.Other
}

func extension(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i:]
	}
	return ""
}
