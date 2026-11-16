package intel

import (
	"testing"

	"github.com/get-sybers/slopmop/internal/indicator"
)

func TestLoadWatchlist(t *testing.T) {
	data := []byte(`[
		{"value": "10.20.1.5", "attribution": "STORM-0940"},
		{"value": "evil.example.com", "type": "Domain", "attribution": "STORM-0940"}
	]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	if wl.Len() != 2 {
		t.Fatalf("Len = %d, want 2", wl.Len())
	}
}

func TestLoadWatchlistRejectsEmptyValue(t *testing.T) {
	data := []byte(`[{"value": "", "attribution": "X"}]`)
	_, err := LoadWatchlist(data)
	if err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestLoadWatchlistRejectsEmptyAttribution(t *testing.T) {
	data := []byte(`[{"value": "10.0.0.1", "attribution": ""}]`)
	_, err := LoadWatchlist(data)
	if err == nil {
		t.Fatal("expected error for empty attribution")
	}
}

func TestLoadWatchlistRejectsTrailingData(t *testing.T) {
	data := []byte(`[{"value": "10.0.0.1", "attribution": "X"}] extra`)
	_, err := LoadWatchlist(data)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestLoadWatchlistRejectsUnknownFields(t *testing.T) {
	data := []byte(`[{"value": "10.0.0.1", "attribution": "X", "extra": true}]`)
	_, err := LoadWatchlist(data)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestMatchHit(t *testing.T) {
	data := []byte(`[{"value": "10.20.1.5", "attribution": "STORM-0940"}]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	indicators := []indicator.Match{
		{Type: "IPv4", Value: "10.20.1.5", Start: 0},
		{Type: "IPv4", Value: "192.168.1.1", Start: 20},
	}
	hits := wl.Match(indicators)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].Value != "10.20.1.5" {
		t.Errorf("hit value = %q, want %q", hits[0].Value, "10.20.1.5")
	}
	if hits[0].Attribution != "STORM-0940" {
		t.Errorf("hit attribution = %q, want %q", hits[0].Attribution, "STORM-0940")
	}
}

func TestMatchCaseInsensitive(t *testing.T) {
	data := []byte(`[{"value": "Evil.Example.Com", "type": "Domain", "attribution": "APT"}]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	indicators := []indicator.Match{
		{Type: "Domain", Value: "evil.example.com", Start: 0},
	}
	hits := wl.Match(indicators)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
}

func TestMatchTypeFilter(t *testing.T) {
	data := []byte(`[{"value": "10.20.1.5", "type": "IPv4", "attribution": "X"}]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	hits := wl.Match([]indicator.Match{
		{Type: "Domain", Value: "10.20.1.5", Start: 0},
	})
	if len(hits) != 0 {
		t.Fatalf("hits = %d, want 0 (type mismatch)", len(hits))
	}
	hits = wl.Match([]indicator.Match{
		{Type: "IPv4", Value: "10.20.1.5", Start: 0},
	})
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
}

func TestMatchDedup(t *testing.T) {
	data := []byte(`[{"value": "10.0.0.1", "attribution": "X"}]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	indicators := []indicator.Match{
		{Type: "IPv4", Value: "10.0.0.1", Start: 0},
		{Type: "IPv4", Value: "10.0.0.1", Start: 50},
	}
	hits := wl.Match(indicators)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1 (deduped)", len(hits))
	}
}

func TestMatchNoEntries(t *testing.T) {
	data := []byte(`[{"value": "10.0.0.1", "attribution": "X"}]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	hits := wl.Match(nil)
	if len(hits) != 0 {
		t.Fatalf("hits = %d, want 0", len(hits))
	}
}

func TestMatchMultipleAttributions(t *testing.T) {
	data := []byte(`[
		{"value": "10.0.0.1", "attribution": "STORM-0940"},
		{"value": "10.0.0.1", "attribution": "APT-29"}
	]`)
	wl, err := LoadWatchlist(data)
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	hits := wl.Match([]indicator.Match{
		{Type: "IPv4", Value: "10.0.0.1", Start: 0},
	})
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want 2 (two attributions)", len(hits))
	}
}

func TestCampaigns(t *testing.T) {
	wl, err := LoadWatchlist([]byte(`[
		{"value": "10.20.1.5", "attribution": "STORM-0940"},
		{"value": "a.example.com", "attribution": "APT-EXAMPLE"},
		{"value": "b.example.com", "attribution": "STORM-0940"}
	]`))
	if err != nil {
		t.Fatalf("LoadWatchlist: %v", err)
	}
	want := []Campaign{{"APT-EXAMPLE", 1}, {"STORM-0940", 2}}
	got := wl.Campaigns()
	if len(got) != len(want) {
		t.Fatalf("Campaigns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Campaigns[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
