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

A version is a package on the GitHub Container Registry that holds the Windows x64 binary and its
SHA-256. [`oras`](https://oras.land) writes the two into the current folder:

```sh
oras pull ghcr.io/get-sybers/slopmop:v<version>
```

The binary is not code-signed. It carries an attestation of its provenance, and its stamp names its
version and its commit:

```sh
sha256sum --check slopmop-<version>-windows-amd64.exe.sha256
gh attestation verify slopmop-<version>-windows-amd64.exe -R Get-Sybers/slopMop
go version -m slopmop-<version>-windows-amd64.exe
```

The versions up to 0.6.2 are GitHub releases, each with the binary and its SHA-256.

## Use

```sh
slopmop -inputdir <folder> report
```

That one command reads every file in the folder and below it, analyses them once, prints the
report and saves it. Nothing is remembered between runs.

```text
$ slopmop -inputdir case42/ai_workdir report
slopmop report   case42/ai_workdir
[x] HIGH - 4 impacts: 2 high, 2 low
[x] high   [!] medium   [i] low

Summary
  files       16  6 scripts, 9 outputs
  indicators  13  1 Base64Blob, 4 Domain, 1 EncodedCommand, 1 GUID, 3 IPv4, 3 SHA1
  activities  1
  tactics     4
  targeted    6   Hostnames 3, IP addresses 3
  exposed     10  Usernames 2, Tenants 2, Devices 3, IP addresses 3

Tactics   (tactic, identifiers, files)
  [x] CredentialAccess  TA0006, AML.TA0013  20250302_090900_step03_sync_retry.ps1, 20250302_092200_step05_export.ps1
  [x] LateralMovement   TA0008, AML.TA0015  20250302_090500_step02_sync.ps1, 20250302_090900_step03_sync_retry.ps1, 20250302_091500_step04_certs.ps1
```

The report has nine sections. Name any after `report` to print only those; the saved files always
hold all of them.

| Section | Holds |
| --- | --- |
| `summary` | the counts |
| `tactics` | each tactic the files show, most severe first, with its ATT&CK and ATLAS identifiers, the files that show it and the ARTEX intents those files are of |
| `timeline` | what was done, in order of time, as a line of blocks: one for each ARTEX intent `i<number>`, or for each period of files that show the same tactics where no file names an intent, with each ATT&CK technique its files show and the tactic and ATLAS technique that follow from it |
| `findings` | each activity, most severe first, with the lines that show it |
| `targeted` | the IP addresses, hostnames and email addresses the scripts name outright, without the hosts of vendors that any script reaches for, whether the attacker knew each beforehand, and what each activity acted on: a task with what it runs, an archive, a file |
| `exposure` | the passwords and other secrets with whose each is and what it is used against, usernames, email addresses, tenants, SSH keys with their hosts, API keys with their services, applications, cloud resources, devices and IP addresses the files hold, and what is of Microsoft 365 and of Google Cloud; a token or a value in base64 is written decoded |
| `impact` | what the findings mean, with the exposed accounts and credentials each concerns |
| `remediation` | what to do, most urgent first, with the exposed accounts and credentials each concerns |
| `mitigation` | what MITRE ATT&CK and MITRE ATLAS say prevents the techniques found, with the exposed accounts and credentials each concerns |

| Command | What it does |
| --- | --- |
| `slopmop -inputdir <folder> report` | prints and saves every section |
| `slopmop -inputdir <folder> report impact remediation` | prints only the sections named |
| `slopmop -inputdir <folder> report -intelfile <file>` | attributes the indicators a watchlist matches |
| `slopmop -inputdir <folder> report -outdir <folder>` | saves the output to the folder named |
| `slopmop -inputdir <folder> report -cores 50 -memory 25` | uses half of the processors of the machine and tries to stay within a quarter of its memory |
| `slopmop -inputdir <folder> report -start 2026-10-22 -stop 2026-10-23` | reads only the files of that time: by the time in a file's name, or else when it was last modified |
| `slopmop -inputdir <folder> report -start 2026-10-22T09:30` | looks forward from that time; `-stop` alone looks back from it |
| `slopmop -inputdir <folder> report -progress hidden` | says nothing of how far the run is; on a terminal a run says so on one line when this is not given |
| `slopmop -inputdir <folder> --help` | says what the line holds so far and what can follow it; `--help` works at every point |

The output is saved to `slopmop-<folder name>` in the current directory, never into the folder
that is read. A password, a hash, a token and a key are written as they stand in the evidence,
so the output folder is to be kept as the evidence is.

| File | Holds |
| --- | --- |
| `report.html` | the report, every section, as one page for a browser |
| `report.md` | the report, every section, as Markdown |
| `report.txt` | the report, every section, as plain text |
| `files.csv` | every file with its whole path, role, size, line count, times and SHA-256 |
| `trace.json` | the timeline |
| `intents.csv` | the ARTEX intents: the period, the techniques and the files of each |
| `findings.json` | the activities, indicators and tactics, each with when it was seen and its lines of evidence |
| `targeted.json` | what the scripts name outright |
| `exposure.csv` | what the files hold, each value as it stands and, where it is encoded, decoded |
| `report.json` | every row of the report, with what each impact and action acts on and the lines that show it |

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
