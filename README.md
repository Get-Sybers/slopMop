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

`slopmop -inputdir <folder> report` reads every file in the folder and below it, analyses them once
and prints the report: the counts, the timeline, the findings, the notable files, the exposure, the
impact, the remediation and the mitigation. The exposure lists the usernames, email addresses,
passwords and other secrets, devices and IP addresses the files hold. An impact, an action and a
mitigation each name what they concern and quote the lines that show it. It saves the same
analysis to `slopmop-<folder name>` in the current directory: `report.txt` to read, and
`files.json`, `trace.json`, `findings.json`, `exposure.json` and `report.json` for a program.
Nothing is written into the folder that is read, and a secret is written masked.

```text
$ slopmop -inputdir case42/ai_workdir report
slopmop report   case42/ai_workdir
[x] HIGH - 4 impacts: 2 high, 1 medium, 1 low
[x] high   [!] medium   [i] low

Summary
  files       16  6 scripts, 9 outputs
  indicators  13  1 Base64Blob, 4 Domain, 1 EncodedCommand, 1 GUID, 3 IPv4, 3 SHA1
  activities  1
  tactics     4
  exposed     8   Usernames 2, Devices 3, IP addresses 3

Timeline   (step, time, role, file)
  1  20250302_090000  script  20250302_090000_step01_inventory.ps1
      tools       get-date, join-path, get-adcomputer, select-object, export-csv
      tactics     Discovery
      indicators  1
```

| Command | What it does |
| --- | --- |
| `slopmop -inputdir <folder> report` | prints and saves every section |
| `slopmop -inputdir <folder> report impact remediation` | prints only the sections named |
| `slopmop -inputdir <folder> report -intelfile <file>` | attributes the indicators a watchlist matches |
| `slopmop -inputdir <folder> report -outdir <folder>` | saves the output to the folder named |
| `slopmop -inputdir <folder> report -secrets shown` | writes each password, hash, token and key as it stands |
| `slopmop -inputdir <folder> --help` | prints what the line holds so far and what can follow it; `--help` works at every point |

The sections are `summary`, `timeline`, `findings`, `files`, `exposure`, `impact`, `remediation`
and `mitigation`. `report` is the one verb, and nothing is remembered between runs.

## Layout

| Path | Holds |
| --- | --- |
| `cmd/slopmop/` | the command: wiring and exit codes |
| `internal/cli/` | the command grammar: parser, registry, dispatch, help |
| `internal/command/` | the verbs, declared in `commands.json` and bound to the packages that do the work |
| `internal/render/` | the report as plain lines and a table as JSON; escapes evidence text |
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
