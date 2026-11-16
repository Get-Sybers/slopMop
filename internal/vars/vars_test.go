package vars

import (
	"maps"
	"testing"
)

func TestRead(t *testing.T) {
	text := "export A=/tmp/a\nB = \"two words\"\n$c = 'three';\r\nset D=four\nE=$(date)\nF=\nA=/tmp/last\n  G=%TEMP%\\g\n" +
		"USER=\"${AD_USER:-svc_backup}\"\nif [ x = y ]; then\n"
	got := Read(text)
	want := Set{"a": "/tmp/last", "b": "two words", "c": "three", "d": "four", "user": "svc_backup"}
	if !maps.Equal(got, want) {
		t.Errorf("Read = %v, want %v", got, want)
	}
	tests := []struct {
		ref   string
		value string
		ok    bool
	}{
		{"$A", "/tmp/last", true},
		{"${b}", "two words", true},
		{"%D%", "four", true},
		{"${X:-fallback}", "fallback", true},
		{"${X:-}", "", false},
		{"$missing", "", false},
		{"$A/x", "", false},
		{"plain", "", false},
	}
	for _, tt := range tests {
		if value, ok := got.Value(tt.ref); value != tt.value || ok != tt.ok {
			t.Errorf("Value(%q) = %q, %t; want %q, %t", tt.ref, value, ok, tt.value, tt.ok)
		}
	}
	for text, want := range map[string]string{
		"$A/x and ${b}": "/tmp/last/x and two words", "$missing@host": "$missing@host", "plain": "plain", "${c}$d": "threefour",
	} {
		if expanded := got.Expand(text); expanded != want {
			t.Errorf("Expand(%q) = %q, want %q", text, expanded, want)
		}
	}
}
