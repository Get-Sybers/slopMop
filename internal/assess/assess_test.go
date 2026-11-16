package assess

import (
	"slices"
	"testing"

	"github.com/get-sybers/slopmop/internal/tactic"
)

func names(results []Result) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.Name)
	}
	return out
}

func TestLoadTable(t *testing.T) {
	table, err := LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	if len(table.impacts) == 0 || len(table.actions) == 0 {
		t.Fatalf("%d impacts and %d actions, want some of each", len(table.impacts), len(table.actions))
	}
	activities, tactics, indicators := table.Names()
	for what, list := range map[string][]string{"activities": activities, "tactics": tactics, "indicators": indicators} {
		sorted := slices.Clone(list)
		slices.Sort(sorted)
		if len(list) == 0 || len(slices.Compact(sorted)) != len(list) {
			t.Errorf("Names() %s = %q, want some and none twice", what, list)
		}
	}
	if !table.Covers("KeyVaultSecretRead") || table.Covers("NoSuchActivity") {
		t.Error("Covers is wrong about an activity")
	}
}

func TestNothingFoundGivesNothing(t *testing.T) {
	table, err := LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Impacts(Evidence{}); got != nil {
		t.Errorf("impacts of no evidence = %+v", got)
	}
	if got := table.Actions(Evidence{}); got != nil {
		t.Errorf("actions of no evidence = %+v", got)
	}
}

func TestImpacts(t *testing.T) {
	table, err := LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	found := Evidence{
		Activities: map[string][]string{
			"KeyVaultSecretRead":        {"vault.sh", "agent.jsonl"},
			"GraphDirectoryEnumeration": {"recon.ps1"},
		},
		Tactics: map[string][]string{"CredentialAccess": {"dump.ps1"}, "LateralMovement": {"move.sh"}},
		Hits:    map[string][]string{"STORM-0940": {"vault.sh"}, "APT-EXAMPLE": {"move.sh"}},
		Indicators: map[string]map[string][]string{
			"vault.sh":    {"KeyVaultEndpoint": {"https://b.vault.azure.net/secrets", "https://a.vault.azure.net/secrets/db?api-version=7.4"}, "IPv4": {"10.0.0.1"}},
			"agent.jsonl": {"KeyVaultEndpoint": {"https://a.vault.azure.net/secrets"}},
		},
	}
	got := table.Impacts(found)
	want := []string{"Credentials exposed", "Known threat infrastructure involved", "Movement to other systems", "Environment mapped"}
	if !slices.Equal(names(got), want) {
		t.Fatalf("impacts = %q, want %q", names(got), want)
	}
	creds := got[0]
	if creds.Level != tactic.High || creds.Kind != "" {
		t.Errorf("credentials impact = %+v, want a high impact", creds)
	}
	if want := []string{"KeyVaultSecretRead", "CredentialAccess tools"}; !slices.Equal(creds.Basis, want) {
		t.Errorf("basis = %q, want %q", creds.Basis, want)
	}
	if want := []string{"agent.jsonl", "dump.ps1", "vault.sh"}; !slices.Equal(creds.Files, want) {
		t.Errorf("files = %q, want %q", creds.Files, want)
	}
	if want := []string{"a.vault.azure.net", "b.vault.azure.net"}; !slices.Equal(creds.Affected, want) || creds.More != 0 {
		t.Errorf("affected = %q and %d more, want %q", creds.Affected, creds.More, want)
	}
	if want := []string{"watchlist APT-EXAMPLE", "watchlist STORM-0940"}; !slices.Equal(got[1].Basis, want) {
		t.Errorf("watchlist basis = %q, want %q", got[1].Basis, want)
	}
	if got[3].Level != tactic.Low {
		t.Errorf("the last impact is %s, want the least severe", got[3].Level)
	}
}

func TestAffectedIsBounded(t *testing.T) {
	table, err := LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	var mail []string
	for _, c := range "abcdefgh" {
		mail = append(mail, string(c)+"@corp.example")
	}
	found := Evidence{
		Activities: map[string][]string{"MailboxAccess": {"collect.py"}},
		Indicators: map[string]map[string][]string{"collect.py": {"Email": mail}},
	}
	got := table.Impacts(found)
	if len(got) != 1 || len(got[0].Affected) != maxAffected || got[0].More != len(mail)-maxAffected {
		t.Errorf("impacts = %+v, want %d addresses listed and %d more", got, maxAffected, len(mail)-maxAffected)
	}
}

func TestActions(t *testing.T) {
	table, err := LoadTable()
	if err != nil {
		t.Fatal(err)
	}
	found := Evidence{
		Activities: map[string][]string{"EventLogClearing": {"clean.bat"}, "RunKeyPersistence": {"persist.ps1"}},
		Hits:       map[string][]string{"STORM-0940": {"persist.ps1"}},
	}
	got := table.Actions(found)
	want := []string{
		"Remove persistence", "Block and hunt the infrastructure", "Recover the missing logs",
		"Send logs off the host", "Alert on new autostart entries",
	}
	if !slices.Equal(names(got), want) {
		t.Fatalf("actions = %q, want %q", names(got), want)
	}
	for i, r := range got {
		wantKind := Remediation
		if i >= 3 {
			wantKind = Mitigation
		}
		if r.Kind != wantKind || r.Text == "" || len(r.Basis) == 0 || len(r.Files) == 0 {
			t.Errorf("action %d = %+v, want a %s with text, basis and files", i, r, wantKind)
		}
	}
	if got[0].Level != tactic.High || got[2].Level != tactic.Medium {
		t.Errorf("priorities = %s then %s, want high before medium", got[0].Level, got[2].Level)
	}
}

func TestDecodeRejects(t *testing.T) {
	impact := `[{"name":"I","severity":"high","statement":"s","activities":["A"]}]`
	action := `[{"name":"R","kind":"remediation","priority":"high","action":"a","tactics":["T"]}]`
	if _, err := decode([]byte(impact), []byte(action)); err != nil {
		t.Fatalf("the smallest valid tables: %v", err)
	}
	tests := map[string][2]string{
		"impacts not json":       {`[`, action},
		"actions not json":       {impact, `{`},
		"trailing data":          {impact + ` x`, action},
		"unknown field":          {`[{"name":"I","severity":"high","statement":"s","activities":["A"],"extra":1}]`, action},
		"empty name":             {`[{"name":"","severity":"high","statement":"s","activities":["A"]}]`, action},
		"named twice":            {`[{"name":"I","severity":"high","statement":"s","activities":["A"]},{"name":"I","severity":"low","statement":"s","watchlist":true}]`, action},
		"no statement":           {`[{"name":"I","severity":"high","statement":"","activities":["A"]}]`, action},
		"bad severity":           {`[{"name":"I","severity":"dire","statement":"s","activities":["A"]}]`, action},
		"nothing triggers":       {`[{"name":"I","severity":"high","statement":"s"}]`, action},
		"bad kind":               {impact, `[{"name":"R","kind":"advice","priority":"high","action":"a","tactics":["T"]}]`},
		"bad priority":           {impact, `[{"name":"R","kind":"mitigation","priority":"urgent","action":"a","tactics":["T"]}]`},
		"an action named twice":  {impact, `[{"name":"R","kind":"mitigation","priority":"low","action":"a","watchlist":true},{"name":"R","kind":"mitigation","priority":"low","action":"a","watchlist":true}]`},
		"an action with no text": {impact, `[{"name":"R","kind":"mitigation","priority":"low","action":"","watchlist":true}]`},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data[0]), []byte(data[1])); err == nil {
				t.Errorf("decode gave no error")
			}
		})
	}
}
