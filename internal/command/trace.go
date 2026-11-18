package command

import (
	"fmt"
	"os"
	"strings"

	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/render"
	"github.com/get-sybers/slopmop/internal/trace"
)

func loadIntelFile(path string) (intel.Watchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return intel.Watchlist{}, fmt.Errorf("-intelfile: %w", err)
	}
	return intel.LoadWatchlist(data)
}

// traceRow fills one row. render has no list value, so a list is one text
// cell joined with ", ".
func traceRow(s trace.Step, intent string, columns []render.Column) ([]render.Value, error) {
	list := func(items []string) render.Value {
		return render.Text(strings.Join(items, ", "))
	}
	cells := map[string]render.Value{
		"step":       render.Int(int64(s.Turn)),
		"name":       render.Text(s.File.Path),
		"role":       render.Text(string(s.File.Role)),
		"time":       when(s.File.Time()),
		"intent":     render.NotApplicable(),
		"tools":      render.NotApplicable(),
		"tactics":    render.NotApplicable(),
		"transforms": render.NotApplicable(),
		"activities": render.NotApplicable(),
		"outputs":    render.NotApplicable(),
		"indicators": render.NotApplicable(),
		"intel":      render.NotApplicable(),
		"note":       render.NotApplicable(),
	}
	if intent != "" {
		cells["intent"] = render.Text(intent)
	}
	if len(s.Tools) > 0 {
		cells["tools"] = list(s.Tools)
	}
	if len(s.Tactics) > 0 {
		cells["tactics"] = list(s.Tactics)
	}
	if len(s.Transforms) > 0 {
		cells["transforms"] = list(s.Transforms)
	}
	if len(s.Activities) > 0 {
		names := make([]string, len(s.Activities))
		for i, a := range s.Activities {
			names[i] = a.Name
		}
		cells["activities"] = list(names)
	}
	if len(s.Outputs) > 0 {
		cells["outputs"] = list(s.Outputs)
	}
	if s.Indicators > 0 {
		cells["indicators"] = render.Int(int64(s.Indicators))
	}
	if len(s.IntelHits) > 0 {
		labels := make([]string, len(s.IntelHits))
		for i, h := range s.IntelHits {
			labels[i] = h.Attribution + ": " + h.Value
		}
		cells["intel"] = list(labels)
	}
	if s.File.Note != "" {
		cells["note"] = render.Text(string(s.File.Note))
	}
	return orderCells("trace", cells, columns)
}
