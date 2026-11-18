package command

import (
	"slices"
	"strings"

	"github.com/get-sybers/slopmop/internal/activity"
	"github.com/get-sybers/slopmop/internal/evidence"
	"github.com/get-sybers/slopmop/internal/exposure"
	"github.com/get-sybers/slopmop/internal/trace"
)

// maxShown is how many lines one output keeps as evidence of what the
// accounts and the identifiers it holds show.
const maxShown = 12

// sighting is one line of an output that shows something by the shape of
// what it holds: an account the scripts collected, or an identifier.
type sighting struct {
	file string
	// line is 0 for an output that has no lines; the subject then stands for itself.
	line    int
	subject string
	shown   exposure.Shown
	// plain marks a shape that says the least of its subject.
	plain bool
}

// discover gives each output what it shows by the shape of what it holds
// first: an account the scripts collected, or a security identifier. What an
// output holds again, and what a script brought, shows nothing.
func (p pipeline) discover(steps []trace.Step, texts map[string]string, all []exposed) {
	split := map[string][]string{}
	lines := func(file string) []string {
		if _, ok := split[file]; !ok {
			split[file] = strings.Split(texts[file], "\n")
		}
		return split[file]
	}
	seen := p.accounts(all, lines)
	seen = append(seen, p.identifiers(steps, texts, lines)...)
	if len(seen) == 0 {
		return
	}
	// A shape that says the least counts where nothing says more: of the
	// same account or identifier in that output, or of the same line.
	type place struct {
		file, subject string
		line          int
	}
	said := map[place]bool{}
	for _, s := range seen {
		if !s.plain {
			said[place{file: s.file, subject: s.subject}] = true
			said[place{file: s.file, line: s.line}] = s.line > 0
		}
	}
	type key struct{ file, activity string }
	type sight struct {
		technique string
		lines     []int
		values    []string
	}
	sights := map[key]*sight{}
	for _, s := range seen {
		if s.plain && (said[place{file: s.file, subject: s.subject}] || said[place{file: s.file, line: s.line}]) {
			continue
		}
		at := sights[key{s.file, s.shown.Activity}]
		if at == nil {
			at = &sight{technique: s.shown.Technique}
			sights[key{s.file, s.shown.Activity}] = at
		}
		switch {
		case s.line == 0:
			at.values = appendUnique(at.values, s.subject)
		case !slices.Contains(at.lines, s.line):
			at.lines = append(at.lines, s.line)
		}
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
					hit.Evidence = append(hit.Evidence, activity.Evidence{Line: n, Text: quoted(lines(file)[n-1])})
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

// accounts lists what the accounts the scripts collected show. An account
// was found by the output that holds it first, and each line of that output
// that names it shows what the shape of the account says there.
func (p pipeline) accounts(all []exposed, lines func(string) []string) []sighting {
	var seen []sighting
	for _, e := range all {
		if !e.kind.Account || e.seen != seenCollected || e.begun.file == "" {
			continue
		}
		file, named := e.begun.file, false
		for _, c := range e.named {
			if c.file != file || c.line < 1 || c.line > len(lines(file)) {
				continue
			}
			if shown, plain, ok := p.exposures.Collected(e.kind.Name, e.value, e.services, lines(file)[c.line-1]); ok {
				seen, named = append(seen, sighting{file: file, line: c.line, subject: e.value, shown: shown, plain: plain}), true
			}
		}
		if named {
			continue
		}
		// An account of an output that has no lines stands for itself.
		if shown, plain, ok := p.exposures.Collected(e.kind.Name, e.value, e.services, ""); ok {
			seen = append(seen, sighting{file: file, subject: e.value, shown: shown, plain: plain})
		}
	}
	return seen
}

// identifiers lists what the identifiers of the outputs show. The files are
// read in the order of the timeline: an identifier is found by the output
// that holds it first, and one a script holds first was brought.
func (p pipeline) identifiers(steps []trace.Step, texts map[string]string, lines func(string) []string) []sighting {
	var seen []sighting
	known := map[string]bool{}
	for _, s := range steps {
		file := s.File.Path
		if !p.exposures.MayIdentify(strings.ToLower(texts[file])) {
			continue
		}
		here := map[string]bool{}
		for n, line := range lines(file) {
			for _, found := range p.exposures.Identified(line) {
				subject := strings.ToLower(found.Value)
				if known[subject] && !here[subject] {
					continue
				}
				here[subject] = true
				if s.File.Role != evidence.Script {
					seen = append(seen, sighting{file: file, line: n + 1, subject: found.Value, shown: found.Shown, plain: found.Plain})
				}
			}
		}
		for subject := range here {
			known[subject] = true
		}
	}
	return seen
}

// quoted is a line as evidence quotes it: on one line, its space folded,
// and cut where it runs long.
func quoted(line string) string {
	return shorten(strings.Join(strings.Fields(line), " "))
}
