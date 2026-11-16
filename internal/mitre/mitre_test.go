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
	if got := c.AtlasFor([]string{"T1105"}); got != nil {
		t.Errorf("AtlasFor(T1105) = %q, want none", got)
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
