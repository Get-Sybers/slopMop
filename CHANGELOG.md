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
