package inventory

import (
	"strings"
	"testing"

	"github.com/get-sybers/slopmop/internal/evidence"
)

func TestLoadRoles(t *testing.T) {
	roles, err := LoadRoles()
	if err != nil {
		t.Fatal(err)
	}
	want := []evidence.Role{evidence.Script, evidence.Output, evidence.Other}
	if len(roles) != len(want) {
		t.Fatalf("%d roles, want %d", len(roles), len(want))
	}
	for i, r := range roles {
		if r.Name != want[i] {
			t.Errorf("role %d = %q, want %q", i, r.Name, want[i])
		}
	}
}

func TestDecodeRolesRejects(t *testing.T) {
	const tail = `,{"name":"output","summary":"o","extensions":[".txt"]},{"name":"other","summary":"x"}]}`
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{`, "unexpected"},
		{"unknown field", `{"roles":[],"extra":1}`, "unknown field"},
		{"trailing data", `{"roles":[]} {}`, "after the document"},
		{"too few roles", `{"roles":[{"name":"script","summary":"s"}]}`, "1 roles, want 3"},
		{"wrong order", `{"roles":[{"name":"output","summary":"s"}` + tail, `role 1 is "output"`},
		{"no summary", `{"roles":[{"name":"script","summary":" "}` + tail, "no summary"},
		{"extension without a dot", `{"roles":[{"name":"script","summary":"s","extensions":["sh"]}` + tail, "dot extension"},
		{"upper-case extension", `{"roles":[{"name":"script","summary":"s","extensions":[".SH"]}` + tail, "dot extension"},
		{"extension in two roles", `{"roles":[{"name":"script","summary":"s","extensions":[".txt"]}` + tail, `".txt" is in`},
		{"shebang does not compile", `{"roles":[{"name":"script","summary":"s","shebangs":["("]}` + tail, "shebang"},
		{"fallback with an extension", `{"roles":[{"name":"script","summary":"s"},{"name":"output","summary":"o"},` +
			`{"name":"other","summary":"x","extensions":[".x"]}]}`, "takes no extensions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeRoles([]byte(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("decodeRoles error = %v, want one containing %q", err, c.want)
			}
		})
	}
}
