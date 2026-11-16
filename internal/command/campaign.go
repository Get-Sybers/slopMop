package command

import (
	"errors"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/intel"
	"github.com/get-sybers/slopmop/internal/render"
)

func (e Env) campaignList(v verbSpec) (*cli.Verb, error) {
	if v.Name != "list" || len(v.Aliases) > 0 {
		return nil, errors.New("the global list verb takes its name and alias from cli.ListVerb")
	}
	if _, err := campaignRow(intel.Campaign{}, v.Columns); err != nil {
		return nil, err
	}
	spec := cli.Spec{
		Params:   map[string]string{intelFile: "<file>"},
		Required: []string{intelFile},
	}
	return cli.ListVerb(v.Summary, spec, func(a *cli.Args) error {
		watchlist, err := loadIntelFile(a.Params[intelFile])
		if err != nil {
			return err
		}
		table := render.Table{Columns: v.Columns}
		for _, c := range watchlist.Campaigns() {
			row, err := campaignRow(c, v.Columns)
			if err != nil {
				return err
			}
			table.Rows = append(table.Rows, row)
		}
		return render.Write(e.Stdout, table, e.options(a.Output))
	}), nil
}

func campaignRow(c intel.Campaign, columns []render.Column) ([]render.Value, error) {
	cells := map[string]render.Value{
		"campaign":   render.Text(c.Attribution),
		"indicators": render.Int(int64(c.Entries)),
	}
	return orderCells("campaign list", cells, columns)
}
