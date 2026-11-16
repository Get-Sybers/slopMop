# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
