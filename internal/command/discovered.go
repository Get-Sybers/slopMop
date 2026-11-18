package command

import (
	"slices"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/trace"
)

// maxShown is how many lines one output keeps as evidence of what the
// accounts it holds show.
const maxShown = 12

// discover gives each output what the accounts it holds show. An account the
// scripts collected was found by the output that holds it first, and the
// shape of the account says which technique of account discovery that is.
func (p pipeline) discover(steps []trace.Step, texts map[string]string, all []exposed) {
	type key struct{ file, activity string }
	type sight struct {
		technique string
		lines     []int
		values    []string
	}
	sights := map[key]*sight{}
	note := func(file string, shown exposure.Shown, lines []int, value string) {
		s := sights[key{file, shown.Activity}]
		if s == nil {
			s = &sight{technique: shown.Technique}
			sights[key{file, shown.Activity}] = s
		}
		for _, n := range lines {
			if !slices.Contains(s.lines, n) {
				s.lines = append(s.lines, n)
			}
		}
		if value != "" {
			s.values = append(s.values, value)
		}
	}
	split := map[string][]string{}
	for _, e := range all {
		if !e.kind.Account || e.seen != seenCollected || e.begun.file == "" {
			continue
		}
		file := e.begun.file
		if _, ok := split[file]; !ok {
			split[file] = strings.Split(texts[file], "\n")
		}
		// Each line of that output that names the account shows what the
		// shape of the account says there.
		shaped, plain := map[exposure.Shown][]int{}, map[exposure.Shown][]int{}
		for _, c := range e.named {
			if c.file != file || c.line < 1 || c.line > len(split[file]) {
				continue
			}
			shown, vague, ok := p.exposures.Collected(e.kind.Name, e.value, e.services, split[file][c.line-1])
			switch {
			case !ok:
			case vague:
				plain[shown] = append(plain[shown], c.line)
			default:
				shaped[shown] = append(shaped[shown], c.line)
			}
		}
		// A line that says nothing of the shape counts for an account that no line says anything of.
		if len(shaped) == 0 {
			shaped = plain
		}
		for shown, lines := range shaped {
			note(file, shown, lines, "")
		}
		if len(shaped) > 0 {
			continue
		}
		// An account of an output that has no lines stands for itself.
		if shown, _, ok := p.exposures.Collected(e.kind.Name, e.value, e.services, ""); ok {
			note(file, shown, nil, e.value)
		}
	}
	if len(sights) == 0 {
		return
	}
	for i := range steps {
		file := steps[i].File.Path
		for _, shown := range p.exposures.Shows() {
			s := sights[key{file, shown.Activity}]
			if s == nil {
				continue
			}
			hit := activity.Hit{
				Name: shown.Activity, Attack: []string{s.technique},
				Tactics: tacticsOf(s.technique, p.tactics, p.catalogue), Lines: len(s.lines) + len(s.values),
			}
			slices.Sort(s.lines)
			for _, n := range s.lines {
				if len(hit.Evidence) < maxShown {
					hit.Evidence = append(hit.Evidence, activity.Evidence{Line: n, Text: quoted(split[file][n-1])})
				}
			}
			for _, value := range s.values {
				if len(hit.Evidence) < maxShown {
					hit.Evidence = append(hit.Evidence, activity.Evidence{Text: quoted(value)})
				}
			}
			steps[i].Activities = append(steps[i].Activities, hit)
			steps[i].Tactics = appendUnique(steps[i].Tactics, hit.Tactics...)
		}
	}
}

// quoted is a line as evidence quotes it: on one line, its space folded,
// and cut where it runs long.
func quoted(line string) string {
	return shorten(strings.Join(strings.Fields(line), " "))
}
