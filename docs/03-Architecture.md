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
| `internal/parse` | extracts commands, variables and file references from bash, PowerShell, Python and batch scripts, and decodes the payloads a file carries encoded |
| `internal/structured` | decodes JSON, XML and HTML reports into their text values and recorded commands using `formats.json` |
| `internal/tactic` | classifies commands by MITRE ATT&CK tactic and ranks each tactic's severity using `tactics.json` |
| `internal/activity` | recognises what a line of evidence does (a role assignment, a mailbox read, a Key Vault secret read) and the tactics of it, using `activities.json` |
| `internal/indicator` | extracts security indicators (IPs, URLs, hashes, CVEs, GUIDs, Microsoft cloud endpoints, OAuth scopes) using `indicators.json` |
| `internal/assess` | turns what a run found into its impacts and the remediation and mitigation they call for, using `impacts.json` and `actions.json` |
| `internal/intel` | matches extracted indicators against an operator-supplied watchlist: a JSON array or a STIX 2.1 bundle; an entry that is an address range matches every address inside it |
| `internal/trace` | reconstructs the timeline from scripts and outputs: ordering, tool extraction, tactic classification, activity detection, indicator counting, output linking |
| `internal/evidencetest` | embeds the fixtures and copies one into a temporary folder for a test |
| `internal/golden` | compares test output with a golden file; owns the `-update` flag |

Imports run one way:

```text
cmd/slopmop -> command -> cli, render, trace -> parse, structured, tactic, activity, intel -> indicator
                       |-> assess -> tactic
                                   |-> inventory -> evidence -> nametime
```

`cli` and `render` import no other internal package. `parse`, `structured`, `tactic`, `activity` and
`indicator` import no other internal package. `evidencetest` and `golden` are imported by tests only.

## 2. Data files

| File | Declares | Checked at load |
| --- | --- | --- |
| `internal/inventory/roles.json` | each role's summary, extensions and shebang patterns | the roles are `script`, `output`, `other` in that order; extensions are lower-case, dotted and in one role; patterns compile; `other` takes neither |
| `internal/command/nouns.json` | nouns, verbs, aliases, summaries, columns | names and summaries present; columns pass the table check; every declared verb has an implementation and every implementation a declaration |
| `internal/tactic/tactics.json` | MITRE ATT&CK tactics, the severity of each and the commands each claims | every tactic has a name, a severity of `low`, `medium` or `high` and at least one command; no command appears in two tactics |
| `internal/activity/activities.json` | each activity's name, tactics and patterns, and the contexts some patterns need | names are present and unique; every activity has a tactic and a pattern; paths and a known context go together; every pattern compiles; `command` rejects a tactic that `tactics.json` lacks |
| `internal/assess/impacts.json` | each impact's name, severity and statement, what triggers it and the indicator types to list as affected | names are present and unique; a statement and a severity of `low`, `medium` or `high`; something triggers each; `command` rejects an activity, a tactic or an indicator type the other tables lack |
| `internal/assess/actions.json` | each action's name, kind, priority and text, and what triggers it | as for an impact; the kind is `remediation` or `mitigation` |
| `internal/indicator/indicators.json` | indicator types and their regex patterns | every entry has a type and a pattern; every pattern compiles |
| `internal/structured/formats.json` | the extensions of each structured format, the field names that hold a command, and the HTML elements that hold a command, are kept verbatim or are dropped | the formats are `json`, `xml`, `html` in that order; extensions are lower-case, dotted and in one format; names are lower-case letters and digits, listed once, and an element is in one list |

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

## 4. Structured reports

`trace list` decodes an output whose extension `formats.json` claims before it looks for indicators
and commands. A script is never decoded this way.

- JSON: every document in the file is read, so JSON Lines is read whole. Each string value and each
  object key is a text value, with its escapes decoded.
- XML: character data, CDATA, attribute values and comments are text values, with entities decoded.
  No external entity or document type definition is resolved.
- HTML: tags are stripped. Text, attribute values and comments are text values, with entities
  decoded. The body of `script` is kept verbatim and the body of `style` is dropped.
- Indicators are extracted from the text values, one per line, so an escaped URL or path is matched
  in its decoded form.
- A command is the text under a command field (a JSON key, an XML element or an XML attribute, with
  case, `_` and `-` ignored) or inside an HTML command element. A JSON list whose strings hold no
  space is one argument vector; otherwise each string is a command line.
- A command is parsed as PowerShell when it holds a `Verb-Noun` cmdlet or names `powershell` or
  `pwsh`, and as bash otherwise. Its tools, tactics and transforms fill the row of the report. A
  report is not a turn and links no output.
- A JSON or XML file that is not well formed is read as plain text. HTML is decoded whatever its form.

`--intelfile` takes a JSON array of entries or a STIX 2.1 bundle. From a bundle, every quoted
literal that an equality compares in the pattern of an `indicator` object is one entry, attributed
to the name of the indicator, or to its id when it has no name.

## 5. File-name timestamps

`nametime.Detect` tries a date and time, then a 10-digit Unix epoch between 1500000000 and
1999999999 (three more digits are read as milliseconds and dropped), then a date. Each rule looks
at its first match only, a stamp never touches another digit, and an impossible calendar date
abandons its rule. A date and time without `Z` is marked local: the name does not state its zone.

## 6. Fixtures

`internal/evidencetest/testdata/bash` and `powershell` are the evidence folders of the
AgentScriptTrace golden test in the VelociSacci repository (`tests/golden/fixtures/`), copied byte
for byte. They hold CRLF, UTF-16, byte-order-mark and binary files on purpose.

`entra` and `lolbin` belong to this repository. `entra` is an agent's run against Entra ID,
Microsoft Graph and Azure Key Vault in bash, PowerShell and Python, with a JSON Lines log; it shows
the cloud activities of `activities.json` except the plain role assignment. `lolbin` is a run on a
Windows host with living-off-the-land binaries and .NET: six PowerShell scripts, a batch file, C#
source, an MSBuild project and a process-creation log, on documentation addresses.

- `.gitattributes` marks every `testdata` path `-text`, so a checkout never converts them.
- `.gitignore`, `.editorconfig`, `.yamllint`, `.gitleaks.toml` and the fixer hooks leave `testdata` alone.
- A checkout does not keep modified times, so `<fixture>.times.json` states one per file and
  `evidencetest.Copy` applies it. Each is three seconds after the file-name timestamp, so the two
  never coincide in a golden file.

## 7. Activities

A tactic table names the command that ran. `curl`, `Invoke-RestMethod` and `az` say nothing about
what a call does, so `activity.Detect` reads the text of every file, script or output, and names
the operations it shows.

- An activity is found where one of its patterns matches a line. A command continued over lines
  with a bash backslash or a PowerShell backtick is one line.
- A script often keeps a host in one variable and builds each address from it. An activity can
  therefore declare `paths`: patterns that count only in a text that matches the activity's
  `context` somewhere, such as the Microsoft Graph host. Graph resource names in a path are matched
  in their documented case, so `/Users/bob` is not `/users`.
- `unless` drops a line: a read is not counted as a write, and the most specific activity wins.
- A pattern is tried only on the lines that hold a literal every match of it must hold. The
  literals are derived from the pattern at load, and a test fails when a pattern has none.
- A step's tactics are those of its tools plus those of its activities.
- `report list` counts, for each activity, the lines that show it. A loop counts once: the tool
  does not run the script.
- A name has a tactic in `tactics.json` only when the name alone says what the command does.
  `certutil`, `bitsadmin`, `reg`, `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod` and the
  Python `requests` calls have none: the activity found on the line gives one.

| Activity | Tactics |
| --- | --- |
| `GlobalAdministratorAssignment` | PrivilegeEscalation, Persistence |
| `RoleAssignment` | PrivilegeEscalation, Persistence |
| `AppRoleAssignment` | Persistence, PrivilegeEscalation |
| `AppCredentialAddition` | Persistence |
| `TokenRequest` | InitialAccess |
| `GraphDirectoryEnumeration` | Discovery |
| `MailboxAccess` | Collection |
| `TeamsMessageAccess` | Collection |
| `SharePointEnumeration` | Collection, Exfiltration |
| `KeyVaultSecretRead` | CredentialAccess |
| `KeyVaultKeyUnwrap` | CredentialAccess |
| `KeyVaultKeyEnumeration` | Discovery |
| `AzureResourceEnumeration` | Discovery |
| `FileDownload` | CommandAndControl |
| `FileUpload` | Exfiltration |
| `DownloadAndExecute` | Execution, CommandAndControl |
| `ReflectiveCodeLoading` | DefenseEvasion, Execution |
| `NativeApiCall` | Execution, DefenseEvasion |
| `RuntimeCompilation` | DefenseEvasion, Execution |
| `ProcessStart` | Execution |
| `NetworkSocket` | CommandAndControl |
| `SignedBinaryProxyExecution` | DefenseEvasion, Execution |
| `RunKeyPersistence` | Persistence |
| `ScheduledTaskCreation` | Persistence, Execution |
| `ServiceCreation` | Persistence, PrivilegeEscalation |
| `EventLogClearing` | DefenseEvasion |
| `LsassDump` | CredentialAccess |
| `RegistryHiveDump` | CredentialAccess |
| `RegistryQuery` | Discovery |
| `CertificateExport` | CredentialAccess |
| `AmsiBypass` | DefenseEvasion |
| `DirectorySearch` | Discovery |

## 8. Windows command lines

`parse.ExtractBatch` reads a `.bat` or `.cmd` file, and the PowerShell parser hands it every
native command it meets: a bare name at the start of a statement, after the call operator, on the
right of an assignment or inside a script block, the target of `Start-Process` and the arguments
of `Process.Start`. A cmdlet is recognised by its Verb-Noun shape instead.

- A command that launches another is followed, four levels deep: `cmd /c`, an inline
  `powershell -Command`, `schtasks /tr`, `forfiles /c`, `wmic process call create`, `start`,
  `call`, and the body of `if` and `for`.
- A here-string and a block comment in a PowerShell script hold data and prose, so no command is
  read from them.
- `certutil -decode`, `-encode`, `-decodehex` and `-encodehex` are transforms.
- A word that ends in `.exe` is a tool unless it is part of an address, the file an output option
  names, or a path built from a variable that the call operator does not run.
- A `.bat` file is a script. A `.cmd` file keeps the output role of `roles.json` and is parsed as
  a batch file all the same.

## 9. Encoded payloads

`parse.Decoded` reads what a file carries encoded, and nothing is run: the argument of a
PowerShell `-EncodedCommand`, in any of its abbreviations, and a Base64 literal handed to
`FromBase64String`. A payload is kept when nearly all of it is printable text.

- The commands of an encoded command join the file's tools, and the text of every payload is
  searched for activities and indicators with the rest of the file.
- Two layers are read: a payload that carries an encoded command is decoded once more.
- A payload over 1 MiB of Base64 is left alone, and a file yields at most 32 payloads.

## 10. Assessment

`report list` ends with what the findings mean and what to do about them. Both come from data
files, and `assess` holds no knowledge of its own.

- An impact or an action applies when one of its triggers is in the evidence: an activity, the
  tactic of a tool that ran, or a watchlist match. The tactics an activity adds do not trigger
  anything: the activity is named directly, so a reflective load is not read as log clearing.
- The basis and the files of each row say why it is there, so a reader can check the claim.
- An impact lists up to five affected values of the indicator types it names, taken from the
  files that show it; an address is cut to its host.
- A test fails when an activity has no impact or no action, so a finding cannot be reported and
  then left out of the assessment.
- A notable file is one whose activities, tool tactics or watchlist matches reach the severity
  asked for. A watchlist match is `high`.
