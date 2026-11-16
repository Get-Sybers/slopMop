package command

import (
	"errors"
	"sort"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/render"
)

type metric struct {
	name  string
	value int
}

func (e Env) reportList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	pipe, err := loadPipeline()
	if err != nil {
		return nil, err
	}
	if _, err := reportRow(metric{}, v.Columns); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Params:   map[string]string{inputDir: "<folder>", intelFile: "<file>"},
		Required: []string{inputDir},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		result, err := pipe.run(a)
		if err != nil {
			return err
		}
		table := render.Table{Columns: v.Columns}
		for _, m := range listMetrics(result) {
			row, err := reportRow(m, v.Columns)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
		}
		return render.Write(e.Stdout, table, e.options(a.Output))
	}), nil
}

// listMetrics counts distinct values across the whole timeline. The intel
// row is present only when a watchlist was given.
func listMetrics(a analysis) []metric {
	roles := map[evidence.Role]int{}
	indicators := map[string]map[string]bool{}
	tactics := map[string]bool{}
	hits := map[string]bool{}
	total := 0
	for _, s := range a.timeline.Steps {
		roles[s.File.Role]++
		for _, name := range s.Tactics {
			tactics[name] = true
		}
		for _, m := range s.Matches {
			if indicators[m.Type] == nil {
				indicators[m.Type] = map[string]bool{}
			}
			if !indicators[m.Type][m.Value] {
				indicators[m.Type][m.Value] = true
				total++
			}
		}
		for _, h := range s.IntelHits {
			hits[h.Type+"\x00"+h.Value+"\x00"+h.Attribution] = true
		}
	}
	metrics := []metric{
		{"files", len(a.timeline.Steps)},
		{"scripts", roles[evidence.Script]},
		{"outputs", roles[evidence.Output]},
		{"indicators", total},
	}
	types := make([]string, 0, len(indicators))
	for typ := range indicators {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		metrics = append(metrics, metric{"indicators " + typ, len(indicators[typ])})
	}
	metrics = append(metrics, metric{"tactics", len(tactics)})
	if a.watchlist != nil {
		metrics = append(metrics, metric{"intel hits", len(hits)})
	}
	return metrics
}

func reportRow(m metric, columns []render.Column) ([]render.Value, error) {
	cells := map[string]render.Value{
		"metric": render.Text(m.name),
		"value":  render.Int(int64(m.value)),
	}
	return orderCells("report list", cells, columns)
}
