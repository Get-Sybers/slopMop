# slopMop

`slopmop` is a static-analysis tool for a folder of scripts an AI agent wrote and the outputs those
scripts produced. It reads the folder. It never executes anything from it, never hands a script to
an interpreter and never writes into it.

## Build

The module needs Go 1.27.4; the `go` command fetches that toolchain when the installed one is older.

```sh
make build      # writes bin/slopmop
make conform    # the gate CI runs
```

Each GitHub release carries a Windows x64 binary, `slopmop-<version>-windows-amd64.exe`, and its
SHA-256. The binary is not code-signed.

## Use

Give it the folder. It reads every file in the folder and below it, analyses them once and prints
the whole analysis: the counts, the timeline, the findings, the notable files, the impact, the
remediation and the mitigation.

```text
$ slopmop case42/ai_workdir
slopmop   case42/ai_workdir
[x] HIGH - 4 impacts: 2 high, 1 medium, 1 low
[x] high   [!] medium   [i] low

Summary
  files       16  6 scripts, 9 outputs
  indicators  13  1 Base64Blob, 4 Domain, 1 EncodedCommand, 1 GUID, 3 IPv4, 3 SHA1
  activities  1
  tactics     4

Timeline   (step, time, role, file)
  1  20250302_090000  script  20250302_090000_step01_inventory.ps1
      tools       get-date, join-path, get-adcomputer, select-object, export-csv
      tactics     Discovery
      indicators  1
```

| Command | What it does |
| --- | --- |
| `slopmop <folder>` | prints every section |
| `slopmop <folder> impact remediation` | prints only the sections named |
| `slopmop <folder> --intelfile <file>` | attributes the indicators a watchlist matches |

The sections are `summary`, `timeline`, `findings`, `files`, `impact`, `remediation` and
`mitigation`. Nothing is remembered between runs.

One view of the same analysis prints as a table or as JSON through the grammar
`slopmop NOUN VERB [selectors] [--params] [output flags] [positional]`:

| Command | What it does |
| --- | --- |
| `slopmop file list --inputdir <folder>` | lists the files directly in the input directory |
| `slopmop file list --inputdir <folder> --recursive` | lists the files in its sub-folders too |
| `slopmop trace list --inputdir <folder>` | traces the scripts and outputs in the input directory |
| `slopmop finding list --inputdir <folder>` | lists the activities, indicators and tactics found |
| `slopmop report list --inputdir <folder>` | reports the counts, the notable files, the impact, and the remediation and mitigation |
| `slopmop campaign list --intelfile <file>` | lists the attributions in a watchlist |

`slopmop` alone prints the usage, the sections and the nouns; `slopmop NOUN` and
`slopmop NOUN VERB -h` print help generated from the command table.

## Layout

| Path | Holds |
| --- | --- |
| `cmd/slopmop/` | the command: wiring and exit codes |
| `internal/cli/` | the command grammar: parser, registry, dispatch, help |
| `internal/command/` | the nouns, declared in `nouns.json` and bound to the packages that do the work |
| `internal/render/` | rows to the screen: default, wide, JSON, quiet |
| `internal/inventory/` | reads the input directory into file records; roles declared in `roles.json` |
| `internal/evidence/` | the record of one file |
| `internal/nametime/` | the timestamp written into a file name |
| `internal/evidencetest/`, `internal/golden/` | fixtures and golden-file comparison for tests |
| `scripts/` | the structural lint, the pinned-linter build and the upgrade |
| `docs/` | command grammar, output schema, architecture, conformance |

## Documents

- [Command grammar](docs/01-Command-Grammar.md)
- [Output schema](docs/02-Output-Schema.md)
- [Architecture](docs/03-Architecture.md)
- [Conformance](docs/04-Conformance.md)
- [Rules for contributors and agents](AGENTS.md)
- [Changelog](CHANGELOG.md)

The Go standard and the gate standard this repository follows are kept in the VelociSacci
repository: `docs/04-Go-Standards.md` and `docs/05-Linting-and-Conformance.md`.

## Licence

Licence: MIT. The text is in [LICENSE](LICENSE).

`internal/mitre/catalogue.json` is derived from MITRE ATT&CK and MITRE ATLAS. Their licences are
beside it, in `LICENSE-ATTACK.txt` and `LICENSE-ATLAS.txt`.
