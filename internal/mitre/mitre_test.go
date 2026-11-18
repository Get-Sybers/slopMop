package mitre

import (
	"slices"
	"testing"
)

func TestLoad(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Attack.HasTechnique("T1105") || c.Attack.HasTechnique("T0000") {
		t.Error("ATT&CK: HasTechnique is wrong about T1105 or T0000")
	}
	if !c.Atlas.HasTechnique("AML.T0102") || !c.Atlas.HasTactic("AML.TA0014") || c.Atlas.HasTactic("TA0011") {
		t.Error("ATLAS: a technique or tactic is missing, or one of ATT&CK is taken for one of ATLAS")
	}
	if got := c.Attack.TacticsOf("T1105"); !slices.Equal(got, []string{"TA0011"}) {
		t.Errorf("tactics of T1105 = %q, want Command and Control", got)
	}
	if got := c.Attack.TacticsOf("T0000"); got != nil {
		t.Errorf("tactics of an unknown technique = %q", got)
	}
}

// A technique has the name of its framework, and a sub-technique that of
// the technique it is part of before its own.
func TestNameOf(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		framework Framework
		id, want  string
	}{
		{"a technique of ATT&CK", c.Attack, "T1105", "Ingress Tool Transfer"},
		{"a sub-technique of ATT&CK", c.Attack, "T1136.001", "Create Account: Local Account"},
		{"a technique of ATLAS", c.Atlas, "AML.T0051", "LLM Prompt Injection"},
		{"a sub-technique of ATLAS", c.Atlas, "AML.T0051.000", "LLM Prompt Injection: Direct"},
		{"a technique the framework lacks", c.Attack, "T0000", ""},
		{"a sub-technique the framework lacks", c.Attack, "T1105.999", ""},
		{"a technique of the other framework", c.Atlas, "T1105", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.framework.NameOf(tt.id); got != tt.want {
				t.Errorf("NameOf(%s) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestMitigationsFor(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := c.Attack.MitigationsFor([]string{"T1105", "T1003.001", "T1105", "T0000"})
	if len(got) < 2 {
		t.Fatalf("mitigations = %+v, want several", got)
	}
	for i, m := range got {
		if m.Name == "" || m.Summary == "" || len(m.Techniques) == 0 {
			t.Errorf("%s lacks a name, a summary or its techniques: %+v", m.ID, m)
		}
		if i > 0 && got[i-1].ID >= m.ID {
			t.Errorf("mitigations are not in order: %s before %s", got[i-1].ID, m.ID)
		}
		if slices.Contains(m.Techniques, "T0000") {
			t.Errorf("%s addresses a technique that does not exist", m.ID)
		}
	}
	ids := func() []string {
		var out []string
		for _, m := range got {
			out = append(out, m.ID)
		}
		return out
	}()
	if !slices.Contains(ids, "M1031") || !slices.Contains(ids, "M1043") {
		t.Errorf("mitigations = %q, want M1031 for the transfer and M1043 for the dump", ids)
	}
	if got := c.Attack.MitigationsFor(nil); len(got) != 0 {
		t.Errorf("mitigations of nothing = %+v", got)
	}
}

func TestAtlasFor(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.AtlasFor([]string{"T1003.001", "T1078.004"}), []string{"AML.T0012", "AML.T0090"}; !slices.Equal(got, want) {
		t.Errorf("AtlasFor = %q, want %q: the technique each is a part of is referred to", got, want)
	}
	if got := c.AtlasFor([]string{"T1053.005"}); got != nil {
		t.Errorf("AtlasFor(T1053.005) = %q, want none", got)
	}
	// What ATLAS leaves unsaid an analogue says, of a technique and of its parts.
	for _, tt := range []struct{ attack, want string }{
		{"T1105", "AML.T0072"}, {"T1048", "AML.T0025"}, {"T1048.003", "AML.T0025"}, {"T1087.004", "AML.T0075"},
	} {
		if got := c.AtlasFor([]string{tt.attack}); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("AtlasFor(%s) = %q, want %s", tt.attack, got, tt.want)
		}
	}
	if got, want := c.AtlasFor([]string{"T1213.002"}), []string{"AML.T0036", "AML.T0126"}; !slices.Equal(got, want) {
		t.Errorf("AtlasFor(T1213.002) = %q, want %q: what ATLAS refers to it and its analogue", got, want)
	}
	if got := c.AtlasFor([]string{"T1087.001"}); got != nil {
		t.Errorf("AtlasFor(T1087.001) = %q, want none: an analogue of one part is not that of another", got)
	}
}

// An analogue names techniques the catalogue lists and adds to what ATLAS says.
func TestPairRejects(t *testing.T) {
	for name, data := range map[string]string{
		"not json":                 `[`,
		"trailing data":            `[] x`,
		"unknown field":            `[{"attack":"T1105","atlas":"AML.T0072","why":"x"}]`,
		"unknown ATT&CK technique": `[{"attack":"T0000","atlas":"AML.T0072"}]`,
		"unknown ATLAS technique":  `[{"attack":"T1105","atlas":"AML.T9999"}]`,
		"what ATLAS says itself":   `[{"attack":"T1078","atlas":"AML.T0012"}]`,
		"what its parent has":      `[{"attack":"T1078.004","atlas":"AML.T0012"}]`,
		"twice":                    `[{"attack":"T1105","atlas":"AML.T0072"},{"attack":"T1105","atlas":"AML.T0072"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.pair([]byte(data)); err == nil {
				t.Error("pair gave no error")
			}
		})
	}
	c, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.pair([]byte(`[{"attack":"T1105","atlas":"AML.T0072"}]`)); err != nil {
		t.Errorf("one analogue: %v", err)
	}
}

func TestDecodeRejects(t *testing.T) {
	frame := func(technique string) string {
		return `{"version":"1","tactics":{"TA1":"A"},"mitigations":{"M1":{"name":"M","summary":"s"}},"techniques":{"T1":` + technique + `}}`
	}
	good := frame(`{"name":"T","tactics":["TA1"],"mitigations":["M1"]}`)
	if _, err := decode([]byte(`{"attack":` + good + `,"atlas":` + good + `}`)); err != nil {
		t.Fatalf("the smallest valid catalogue: %v", err)
	}
	tests := map[string]string{
		"not json":           `{`,
		"trailing data":      `{"attack":` + good + `,"atlas":` + good + `} x`,
		"unknown field":      `{"attack":` + good + `,"atlas":` + good + `,"extra":1}`,
		"an empty framework": `{"attack":` + good + `,"atlas":{}}`,
		"no name":            `{"attack":` + frame(`{"name":"","tactics":[],"mitigations":[]}`) + `,"atlas":` + good + `}`,
		"unknown tactic":     `{"attack":` + frame(`{"name":"T","tactics":["TA9"],"mitigations":[]}`) + `,"atlas":` + good + `}`,
		"unknown mitigation": `{"attack":` + good + `,"atlas":` + frame(`{"name":"T","tactics":[],"mitigations":["M9"]}`) + `}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Error("decode gave no error")
			}
		})
	}
}
