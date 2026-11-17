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

```sh
slopmop -inputdir <folder> report
```

That one command reads every file in the folder and below it, analyses them once, prints the
report and saves it. Nothing is remembered between runs.

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
  targeted    7   Usernames 1, Hostnames 3, IP addresses 3
  exposed     8   Usernames 2, Devices 3, IP addresses 3

Timeline   (step, time, role, file)
  1  20250302_090000  script  20250302_090000_step01_inventory.ps1
      tools       get-date, join-path, get-adcomputer, select-object, export-csv
      tactics     Discovery
      indicators  1
```

The report has ten sections. Name any after `report` to print only those; the saved files always
hold all of them.

| Section | Holds |
| --- | --- |
| `summary` | the counts |
| `timeline` | each file in order, with its tools, tactics and activities |
| `intents` | each ARTEX intent, by its run folder `i<number>`: the period of its files and the ATT&CK and ATLAS techniques found in them |
| `findings` | each activity, indicator and tactic, most severe first, with the lines that show it |
| `files` | the files that hold a finding of high severity |
| `targeted` | the usernames, IP addresses, hostnames and email addresses the scripts name outright, and whether the attacker knew each beforehand |
| `exposure` | the usernames, email addresses, passwords and other secrets, devices and IP addresses the files hold |
| `impact` | what the findings mean, what each concerns and the lines that show it |
| `remediation` | what to do and to what, most urgent first |
| `mitigation` | what MITRE ATT&CK and MITRE ATLAS say prevents the techniques found |

| Command | What it does |
| --- | --- |
| `slopmop -inputdir <folder> report` | prints and saves every section |
| `slopmop -inputdir <folder> report impact remediation` | prints only the sections named |
| `slopmop -inputdir <folder> report -intelfile <file>` | attributes the indicators a watchlist matches |
| `slopmop -inputdir <folder> report -outdir <folder>` | saves the output to the folder named |
| `slopmop -inputdir <folder> report -secrets shown` | writes each password, hash, token and key as it stands |
| `slopmop -inputdir <folder> --help` | says what the line holds so far and what can follow it; `--help` works at every point |

The output is saved to `slopmop-<folder name>` in the current directory, never into the folder
that is read. A password, a hash, a token and a key are written masked.

| File | Holds |
| --- | --- |
| `report.html` | the report, every section, as one page for a browser |
| `report.md` | the report, every section, as Markdown |
| `report.txt` | the report, every section, as plain text |
| `files.json` | every file with its role, size, line count, times and SHA-256 |
| `trace.json` | the timeline |
| `intents.json` | the ARTEX intents |
| `findings.json` | the activities, indicators and tactics |
| `targeted.json` | what the scripts name outright |
| `exposure.json` | what the files hold |
| `report.json` | every row of the report |

## Layout

| Path | Holds |
| --- | --- |
| `cmd/slopmop/` | the command: wiring and exit codes |
| `internal/` | the packages, each described in the [architecture](docs/03-Architecture.md) |
| `scripts/` | the structural lint, the pinned-linter build, the upgrade and the MITRE catalogue builder |
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
