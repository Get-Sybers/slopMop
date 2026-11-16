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

The grammar is `slopmop NOUN VERB [selectors] [--params] [output flags] [positional]`.

| Command | What it does |
| --- | --- |
| `slopmop file list --inputdir <folder>` | lists the files directly in the input directory |
| `slopmop file list --inputdir <folder> --recursive` | lists the files in its sub-folders too |
| `slopmop trace list --inputdir <folder>` | traces the scripts and outputs in the input directory |
| `slopmop finding list --inputdir <folder>` | lists the activities, indicators and tactics found |
| `slopmop report list --inputdir <folder>` | counts them |
| `slopmop campaign list --intelfile <file>` | lists the attributions in a watchlist |

The input directory is always named on the command line with `--inputdir`; nothing is remembered
between runs.

```text
$ slopmop file list --inputdir case42/ai_workdir
NAME                                       ROLE    SIZE   LINES  MODIFIED
20250302_090000_step01_inventory.ps1       script  487 B  13     2025-03-02T09:00:03Z
20250302_090500_step02_sync.ps1            script  385 B  7      2025-03-02T09:05:03Z
20250302_090900_step03_sync_retry.ps1      script  478 B  13     2025-03-02T09:09:03Z
20250302_091500_step04_certs.ps1           script  387 B  7      2025-03-02T09:15:03Z
20250302_092200_step05_export.ps1          script  639 B  12     2025-03-02T09:22:03Z
ca01_20250302_092210.cer                   other   18 B   -      2025-03-02T09:22:13Z
ca_ping_20250302_091540.log                output  162 B  3      2025-03-02T09:15:43Z
cert_store_20250302_091530.txt             output  656 B  7      2025-03-02T09:15:33Z
export_summary_20250302_092215.txt         output  116 B  2      2025-03-02T09:22:18Z
hosts_20250302_090030.csv                  output  200 B  4      2025-03-02T09:00:33Z
sync_10.20.1.17_20250302_090530.txt        output  548 B  3      2025-03-02T09:05:33Z
sync_10.20.1.17_retry_20250302_090930.txt  output  397 B  10     2025-03-02T09:09:33Z
```

`slopmop`, `slopmop NOUN` and `slopmop NOUN VERB -h` print help generated from the command table.

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
