# Architecture

One sentence governs the rest: **one package owns all reading of evidence, the packages that reason
about evidence touch no file, and every static table is a data file validated at load.**

## 1. Packages

| Package | Concern |
| --- | --- |
| `cmd/slopmop` | builds the application, runs it, maps the result to an exit code |
| `internal/cli` | the grammar: flag kinds, parser, noun registry, dispatch, generated help; knows no noun |
| `internal/command` | the nouns: declares them in `nouns.json` and binds each verb to its implementation |
| `internal/render` | prints a table in the default, wide, JSON and quiet views; escapes evidence text |
| `internal/inventory` | walks the input directory and builds one record per file; owns all evidence I/O |
| `internal/evidence` | the file record and its vocabularies (role, note); no I/O |
| `internal/nametime` | detects the timestamp written into a file name; no I/O |
| `internal/parse` | extracts commands, variables and file references from bash and PowerShell scripts |
| `internal/tactic` | classifies commands by MITRE ATT&CK tactic and ranks each tactic's severity using `tactics.json` |
| `internal/indicator` | extracts security indicators (IPs, URLs, hashes, CVEs, GUIDs, Microsoft cloud endpoints, OAuth scopes) using `indicators.json` |
| `internal/trace` | reconstructs the timeline from scripts and outputs: ordering, tool extraction, tactic classification, indicator counting, output linking |
| `internal/evidencetest` | embeds the fixtures and copies one into a temporary folder for a test |
| `internal/golden` | compares test output with a golden file; owns the `-update` flag |

Imports run one way:

```text
cmd/slopmop -> command -> cli, render, trace -> parse, tactic, indicator
                                   |-> inventory -> evidence -> nametime
```

`cli` and `render` import no other internal package. `parse`, `tactic` and `indicator` import no
other internal package. `evidencetest` and `golden` are imported by tests only.

## 2. Data files

| File | Declares | Checked at load |
| --- | --- | --- |
| `internal/inventory/roles.json` | each role's summary, extensions and shebang patterns | the roles are `script`, `output`, `other` in that order; extensions are lower-case, dotted and in one role; patterns compile; `other` takes neither |
| `internal/command/nouns.json` | nouns, verbs, aliases, summaries, columns | names and summaries present; columns pass the table check; every declared verb has an implementation and every implementation a declaration |
| `internal/tactic/tactics.json` | MITRE ATT&CK tactics, the severity of each and the commands each claims | every tactic has a name, a severity of `low`, `medium` or `high` and at least one command; no command appears in two tactics |
| `internal/indicator/indicators.json` | indicator types and their regex patterns | every entry has a type and a pattern; every pattern compiles |

All are embedded with `go:embed` and decoded strictly: an unknown field or trailing data is an
error. The selectors of `file list` are the role names, and its columns are the declared columns.

## 3. Reading evidence

The tool keeps no state: every run names its input directory with `--inputdir` and writes only to
standard output and standard error.

- The input directory is opened as a root (`os.OpenRoot`) and every file is opened through it read-only, so
  no path leads outside the folder.
- Only regular files are listed. Symbolic links and special files are skipped without being
  opened. Hidden files are listed.
- A read takes a depth. At depth 0 only the files directly in the folder are listed and sub-folders
  are skipped. `--recursive` reads at `inventory.MaxDepth`, 16 levels of sub-folder. Each
  sub-folder is opened through the same root. A symbolic link to a folder is not walked, so a walk
  cannot loop or leave the folder.
- A file's path is below the input directory and slash separated. Its role and file-name timestamp
  come from the last element only.
- A sub-folder below the depth, or one that cannot be read, is recorded in `Result.Skipped` and the
  verb reports it as an error after the rows.
- Each file is read once. That one pass feeds SHA-256, counts the bytes and keeps the bytes the text
  needs. A file over 64 MiB is hashed and noted `oversize`; its text is not kept.
- A file that cannot be opened or read is listed with the note `unreadable`.
- Encoding: a byte-order mark decides (UTF-32 LE, UTF-16 LE, UTF-16 BE, UTF-8). Without one, a NUL
  in the first 4,096 bytes means `binary`; otherwise the bytes are UTF-8 with invalid sequences
  replaced. CRLF counts as one line break.
- Lines: the number of line breaks, plus one when non-empty text does not end with one.
- Role: by lower-cased extension. A file no extension claims becomes a script when its text opens
  with a shebang pattern.
- `Read` discards text after a record is built, so memory is bounded by one file. `ReadAll` retains
  the decoded text for callers that need it (trace reconstruction).

## 4. File-name timestamps

`nametime.Detect` tries a date and time, then a 10-digit Unix epoch between 1500000000 and
1999999999 (three more digits are read as milliseconds and dropped), then a date. Each rule looks
at its first match only, a stamp never touches another digit, and an impossible calendar date
abandons its rule. A date and time without `Z` is marked local: the name does not state its zone.

## 5. Fixtures

`internal/evidencetest/testdata/bash` and `powershell` are the evidence folders of the
AgentScriptTrace golden test in the VelociSacci repository (`tests/golden/fixtures/`), copied byte
for byte. They hold CRLF, UTF-16, byte-order-mark and binary files on purpose.

- `.gitattributes` marks every `testdata` path `-text`, so a checkout never converts them.
- `.gitignore`, `.editorconfig`, `.yamllint`, `.gitleaks.toml` and the fixer hooks leave `testdata` alone.
- A checkout does not keep modified times, so `<fixture>.times.json` states one per file and
  `evidencetest.Copy` applies it. Each is three seconds after the file-name timestamp, so the two
  never coincide in a golden file.
