# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `finding list --inputdir <folder>`: one finding per distinct indicator and per tactic, with
  severity, contributing files and, with `--intelfile`, attribution. Selectors `-indicator` and
  `-tactic`.
- `report list --inputdir <folder>`: summary metrics of an analysis: files, scripts, outputs,
  distinct indicators in total and by type, distinct tactics and, with `--intelfile`, intel hits.
- `campaign list --intelfile <file>`: the distinct attributions in a watchlist with their entry
  counts.
- A `severity` of `low`, `medium` or `high` for each tactic in `internal/tactic/tactics.json`.
- `--intelfile <file>` parameter for `trace list`: loads a JSON watchlist of known indicators and
  matches them against extracted IoCs, showing attributions in the new INTEL column.
- Package `internal/intel` for loading and matching threat intelligence watchlists.
- Go module `github.com/get-sybers/slopmop` with the command `slopmop`.
- Command grammar `slopmop NOUN VERB [selectors] [--params] [output flags] [positional]` with
  enforced flag prefixes, generated help and exit codes 0, 1 and 2.
- `file list --inputdir <folder>`: the inventory of the input directory with role, size, line
  count, modified time, SHA-256, file-name timestamp and note. `--inputdir` is required.
- Output views: default, `-o wide`, `-o json`, `-q`, `--no-headers`, `--tz local|utc`, with evidence
  text escaped before it reaches a terminal.
- Data files `internal/command/nouns.json` and `internal/inventory/roles.json`, embedded and
  validated at load.
- Evidence fixtures `bash` and `powershell` with their modified-time manifests.
- `make conform` gate, the structural lint with its regression test, the pinned golangci-lint
  build and `make upgrade`.
- CI workflow with `conform`, `vuln` and `all_green`, and Dependabot for GitHub Actions and Go modules.
- Documents: command grammar, output schema, architecture, conformance, and `AGENTS.md`.
- MIT licence in `LICENSE`, declared in `README.md` and checked by the structural lint.
- `trace list --inputdir <folder>`: timeline reconstruction of AI agent scripts, with command
  extraction, MITRE ATT&CK tactic classification, security indicator extraction and output linking.
- Data files `internal/tactic/tactics.json` (8 ATT&CK tactics) and `internal/indicator/indicators.json`
  (11 indicator patterns), embedded and validated at load.
- Packages `internal/parse` (bash and PowerShell script parsing), `internal/tactic` (command
  classification), `internal/indicator` (IoC extraction) and `internal/trace` (timeline builder).
- Transform detection in `trace list`: Base64, GZip, Deflate, AES and other .NET cryptography,
  XOR, hex encoding, string manipulation, `-EncodedCommand` and `SecureString` in PowerShell;
  base64, xxd, gzip, openssl and related tools in bash. TRANSFORMS column in trace output.
- Staging file extensions `.b64`, `.gz`, `.bin`, `.cmd`, `.ses`, `.enc`, `.dat` and `.raw` recognised
  as output role in the inventory.
- Indicator patterns `Base64Blob` and `EncodedCommand` (13 patterns total).
- PowerShell staging fixture `step06_stage.ps1` with `.b64`, `.ses` and `.cmd` output files.

### Fixed

- The bash parser no longer treats a here-string (`<<<`) or an arithmetic shift (`$((1 << 4))`) as
  a here-doc, which skipped the rest of the script.
- PowerShell cmdlet matching is now case-insensitive.
- Transform labels are consistent across parsers (`GZip`, `Deflate` instead of `gzipstream`,
  `deflatestream`).
- `-e` and `-ec` abbreviations for `-EncodedCommand` are now detected.
- IPv4 indicator pattern has word boundaries and rejects trailing octets (`1.2.3.4.5`).
- Domain indicator pattern rejects .NET namespaces (`System.IO`, `$obj.Count`).
- `trace list` output linking compares by base name, so directory-prefixed writes match.
- Each script is parsed once per `trace list` instead of twice.
- `-o json` and `-o wide` output for `trace list` is no longer truncated.

### Changed

- Helpers shared by the bash and PowerShell parsers live in `internal/parse/helpers.go`.
- Indicator patterns support an optional `not_followed_by` field for boundary checks.
