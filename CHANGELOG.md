# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `report list` lists the notable files after the counts: each script, output or other file that
  holds a finding at or above `--severity` (`high` unless given), with what was found in it and the
  files it is linked to.
- `report list` gives an impact report: what the findings mean, such as credentials exposed,
  persistence established or defences impaired, with the files that show it and the hosts or
  addresses affected.
- `report list` gives a remediation and a mitigation report: the actions the findings call for,
  each with a priority.
- Selectors `-summary`, `-files`, `-impact`, `-remediation` and `-mitigation` for `report list`.
- Package `internal/assess` and its data files `impacts.json` and `actions.json`, embedded and
  validated at load. A test fails when an activity has no impact or no action.
- Activities recognise an upload by `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod` and
  the Python `requests` calls, a download by `wget` and `urlretrieve`, and `curl` piped to a shell.
- `cli.Usagef`, the usage error of a verb that rejects the value of a param.

### Changed

- The columns of `report list` are ITEM, SECTION, VALUE and DETAIL, with BASIS and FILES in the
  wide view; they were METRIC and VALUE. The counts keep their names and are the `summary` section.
- `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod`, the Python `requests` and `urllib`
  calls, `openssl` and `base64` have no tactic of their own: they were Exfiltration whatever they
  did. The activity on the line gives the tactic.
- The Python `socket` calls are CommandAndControl; they were Exfiltration.

## [0.2.1] - 2026-11-16

### Added

- Batch files: `.bat` takes the `script` role, and `parse.ExtractBatch` reads a `.bat` or `.cmd`
  file for commands, variables, redirections and `certutil` transforms.
- Encoded payloads are read, never run: the argument of a PowerShell `-EncodedCommand` and a
  Base64 literal handed to `FromBase64String`, two layers deep. Their commands join the file's
  tools, and their text is searched for activities and indicators.
- Activities for living-off-the-land binaries and .NET: `FileDownload`, `FileUpload`,
  `DownloadAndExecute`, `ReflectiveCodeLoading`, `NativeApiCall`, `RuntimeCompilation`,
  `ProcessStart`, `NetworkSocket`, `SignedBinaryProxyExecution`, `RunKeyPersistence`,
  `ScheduledTaskCreation`, `ServiceCreation`, `EventLogClearing`, `LsassDump`,
  `RegistryHiveDump`, `RegistryQuery`, `CertificateExport`, `AmsiBypass` and `DirectorySearch`.
  They are found in any file, so C# source and an MSBuild project show them too.
- Tactic `CommandAndControl`, and binaries the table lacked: `msiexec`, `regasm`, `regsvcs`,
  `cmstp`, `odbcconf`, `mavinject`, `hh`, `forfiles`, `pcalua`, `ieexec`, `xwizard`, `msdt`,
  `wsl`, `csc`, `vbc`, `jsc`, `ilasm`, `esentutl`, `makecab`, `extrac32`, `expand`, `plink`,
  `frpc`, `ligolo-ng` and `desktopimgdownldr`.
- Evidence fixture `lolbin`: living-off-the-land binaries and .NET on a Windows host.

### Fixed

- The PowerShell parser reports a native command written as a bare name: at the start of a
  statement, after the call operator, on the right of an assignment, inside a script block, as the
  target of `Start-Process` and in the arguments of `Process.Start`. It reported one only when
  the name ended in `.exe`.
- A command that launches another is followed: `cmd /c`, an inline `powershell -Command`,
  `schtasks /tr`, `forfiles /c`, `wmic process call create`, `start` and `call`.
- The PowerShell parser reads no command from a here-string or a block comment.
- A word ending in `.exe` is no longer a tool when it is part of an address, the file an output
  option names, or a path built from a variable.
- A command line in a log that has a drive path, an `.exe` or a slash switch is read as a cmd.exe
  command line, so the command a scheduled task runs is found.

### Changed

- `certutil`, `bitsadmin`, `start-bitstransfer` and `reg` have no tactic of their own: the
  activity on the line gives one (`FileDownload`, `CertificateExport`, `RunKeyPersistence`,
  `RegistryQuery` and others). `certutil` was always CredentialAccess, `bitsadmin` always
  Exfiltration and `reg` always Discovery.
- `ngrok`, `chisel` and `cloudflared` are CommandAndControl; they were Exfiltration.

## [0.2.0] - 2026-11-16

### Added

- Activity detection: `internal/activity` and its data file `activities.json` name what a line of
  evidence does, whichever command carried it: `GlobalAdministratorAssignment`, `RoleAssignment`,
  `AppRoleAssignment`, `AppCredentialAddition`, `TokenRequest`, `GraphDirectoryEnumeration`,
  `MailboxAccess`, `TeamsMessageAccess`, `SharePointEnumeration`, `KeyVaultSecretRead`,
  `KeyVaultKeyUnwrap`, `KeyVaultKeyEnumeration` and `AzureResourceEnumeration`. An address built
  from a variable or by concatenation and a command continued over lines are recognised (#6).
- `trace list`: the ACTIVITIES column, and a step's tactics include those of its activities.
- `finding list`: one row per activity and the selector `-activity`.
- `report list`: `activities` and one row per activity with the number of lines that show it.
- Tactics `InitialAccess` and `PrivilegeEscalation` in `tactics.json`.
- A watchlist entry that is an address range, such as `144.172.64.0/24`, matches every address
  inside it, in a JSON watchlist and in a STIX bundle.
- `--recursive` for `finding list` and `report list`.
- Evidence fixture `entra`: an agent's run against Entra ID, Microsoft Graph and Key Vault.

### Fixed

- The bash parser reads a command continued with a backslash as one command; a later line of it
  is no longer reported as a tool.
- The bash parser no longer reports a word of a `for` list as a tool.

### Changed

- A raw Graph, Key Vault or Azure call still carries the tactic of its command (`curl` and
  `Invoke-RestMethod` are Exfiltration), and now also the tactics of what it does.

## [0.1.0] - 2026-11-16

### Added

- Workflow `release.yml`: run by hand on `main` with a version, it tests on Windows, builds
  `slopmop-<version>-windows-amd64.exe`, runs that file against a fixture and publishes it with its
  SHA-256 as a GitHub release whose notes are the version's section of this file.
- CI job `platform`: the tests and the integration test of the built binary run on Windows and
  macOS, and `all_green` requires it.
- `make cross` also builds windows/arm64 and darwin/amd64.
- Structured report parsing in `trace list`: JSON (and JSON Lines), XML and HTML outputs are decoded
  before indicators are extracted, and the commands they record fill the TOOLS, TACTICS and
  TRANSFORMS columns (#8).
- Package `internal/structured` and its data file `formats.json`, embedded and validated at load.
- `--intelfile` accepts a STIX 2.1 bundle: the literals in the patterns of its indicator objects
  become watchlist entries.
- Extensions `.jsonl`, `.ndjson`, `.html` and `.htm` recognised as output role in the inventory.
- `parse.ExtractCommand`, which chooses the shell of a command line found outside a script.
- Python script parsing: `.py` files and files with a Python shebang take the `script` role, and
  `trace list` extracts their imports, variables, file reads and writes, transforms, network and
  process calls, and the commands those process calls run. The Python calls are classified in
  `tactics.json`.
- `--recursive` switch, short form `-r`, for `file list` and `trace list`: reads the sub-folders of
  the input directory, 16 levels down, and names each file by its path below that directory. A
  sub-folder that is deeper or unreadable is named in an error after the rows. Closes #9.
- Switch flag kind in the grammar: `cli.Spec.Switches` declares a double-dash flag without a value
  and its one-letter short form.
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
- Cloud commands in `tactics.json`: Entra ID, Microsoft Graph, Azure, Key Vault and Exchange Online
  cmdlets for audit-log discovery, Key Vault backup, application and federation persistence,
  audit evasion and mailbox collection.
- Indicator types `GUID`, `GraphEndpoint`, `AzureManagementEndpoint`, `EntraLoginEndpoint`,
  `KeyVaultEndpoint` and `OAuthScope` in `indicators.json`. A Microsoft endpoint is reported under
  its own type, not as `URL`, and a lookalike host is not reported as an endpoint.
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

- A tool named by a path keeps one name on every operating system: the parsers split a path at
  either separator themselves (`parse.BaseName`), where `filepath.Base` gave `nmap.exe` on Windows
  and the whole of `C:\Tools\nmap.exe` elsewhere.
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
