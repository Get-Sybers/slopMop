# Architecture

One sentence governs the rest: **one package owns all reading of evidence, the packages that reason
about evidence touch no file, and every static table is a data file validated at load.**

## 1. Packages

| Package | Concern |
| --- | --- |
| `cmd/slopmop` | builds the application, runs it, maps the result to an exit code |
| `internal/cli` | the grammar: options, verbs, the words after a verb, dispatch, generated help; knows no verb |
| `internal/command` | the verbs: declares them in `commands.json`, binds each to its implementation, and saves the output |
| `internal/render` | writes the report as plain lines, Markdown and HTML, and a table in the default, wide, quiet and JSON views, of which the saved files use JSON; escapes evidence text |
| `internal/inventory` | walks the input directory and builds one record per file; owns all evidence I/O |
| `internal/evidence` | the file record and its vocabularies (role, note); no I/O |
| `internal/nametime` | detects the timestamp written into a file name; no I/O |
| `internal/parse` | extracts commands, variables and file references from bash, PowerShell, Python and batch scripts, and decodes the payloads a file carries encoded |
| `internal/structured` | decodes JSON, XML and HTML reports into their text values and recorded commands using `formats.json` |
| `internal/tactic` | classifies commands by MITRE ATT&CK tactic and ranks each tactic's severity using `tactics.json` |
| `internal/activity` | recognises what a line of evidence does (a role assignment, a mailbox read, a Key Vault secret read) and the tactics of it, using `activities.json` |
| `internal/indicator` | extracts security indicators (IPs, URLs, hashes, CVEs, GUIDs, Microsoft cloud endpoints, OAuth scopes) using `indicators.json` |
| `internal/assess` | turns what a run found into its impacts and the remediation they call for, using `impacts.json` and `actions.json` |
| `internal/exposure` | names what the evidence holds that an attacker can use: usernames, email addresses, passwords and other secrets, devices and IP addresses; masks a secret; no I/O |
| `internal/intent` | names the ARTEX intent a path lies in, by its run folder or its session name; no I/O |
| `internal/device` | reads how many processors and how much memory the machine has, on Linux, Windows and macOS; changes nothing |
| `internal/parallel` | runs independent pieces of work on every processor; no I/O |
| `internal/vars` | reads the variables a script sets to a plain value, so a command that names one is shown with what it holds; no I/O |
| `internal/mitre` | holds the identifiers, names and mitigation links of MITRE ATT&CK and MITRE ATLAS in `catalogue.json` |
| `internal/intel` | matches extracted indicators against an operator-supplied watchlist: a JSON array or a STIX 2.1 bundle; an entry that is an address range matches every address inside it |
| `internal/trace` | reconstructs the timeline from scripts and outputs: ordering, tool extraction, tactic classification, activity detection, indicator counting, output linking |
| `internal/evidencetest` | embeds the fixtures and copies one into a temporary folder for a test |
| `internal/golden` | compares test output with a golden file; owns the `-update` flag |

Imports run one way:

```text
cmd/slopmop -> cli, command, render
command     -> cli, render, inventory, trace, assess, exposure, mitre, activity,
               indicator, intel, intent, structured, tactic, evidence, parallel, device
trace       -> parse, structured, tactic, activity, indicator, intel, evidence, parallel
inventory   -> evidence -> nametime
activity    -> vars, parallel
exposure    -> vars
assess      -> tactic
intel       -> indicator
indicator   -> parallel
parse       -> parallel
```

`cli`, `render`, `structured`, `tactic`, `intent`, `mitre`, `nametime`, `parallel`, `device` and
`vars` import no other internal package. `evidencetest` and `golden` are imported by tests only.

## 2. Data files

| File | Declares | Checked at load |
| --- | --- | --- |
| `internal/inventory/roles.json` | each role's summary, extensions and shebang patterns | the roles are `script`, `output`, `other` in that order; extensions are lower-case, dotted and in one role; patterns compile; `other` takes neither |
| `internal/command/commands.json` | the usage line, the options, the verbs with their sections, hints and saved files, and the columns of each class | names, hints and summaries present and unique; a verb names only declared options; columns pass the table check; a saved file is a file name of its own; a saved report names a format that has a writer, once; every declared verb and section has an implementation and every implementation a declaration; a row fills exactly the declared columns |
| `internal/tactic/tactics.json` | the tactics, the severity of each, its ATT&CK and ATLAS identifiers and the commands it claims | every tactic has a name, a severity of `low`, `medium` or `high`, both identifiers and at least one command; no command appears in two tactics; `command` rejects an identifier the catalogue lacks |
| `internal/activity/activities.json` | each activity's name, tactics, ATT&CK and ATLAS techniques and patterns, the contexts some patterns need, and the subjects a matching line acts on | names are present and unique; every activity has a tactic, an ATT&CK technique and a pattern; `command` rejects a technique the catalogue lacks; paths and a known context go together; every pattern compiles; a subject has a label and a pattern with one group; `command` rejects a tactic that `tactics.json` lacks |
| `internal/assess/impacts.json` | each impact's name, severity and statement, what triggers it, the indicator types to list as affected and the kinds of exposure it concerns | names are present and unique; a statement and a severity of `low`, `medium` or `high`; something triggers each; `command` rejects an activity, a tactic, an indicator type or a kind of exposure the other tables lack |
| `internal/assess/actions.json` | each remediation's name, priority and text, and what triggers it | as for an impact |
| `internal/exposure/exposures.json` | each kind of exposure: its title, its severity, whether it is a secret, the field names and endings that hold it, the indicator types that are of it, what a value must and must not look like, and its patterns | names, titles and severities present and unique; a field name is lower-case letters and digits and in one kind; an ending has three characters or more; an indicator type is in one kind and `command` rejects one that `indicators.json` lacks; every expression compiles; a pattern has a group named `value` and a lower-case text a line must hold; `command` rejects a severity that is not `low`, `medium` or `high` |
| `internal/intent/paths.json` | the rules that find an ARTEX intent in a path, in the order they are tried, and the folder names that are none | a rule has a name of its own and a pattern that compiles with a group named `id` and no group but `id` and `task`; a rejected name is present once |
| `internal/mitre/catalogue.json` | for ATT&CK and for ATLAS: the version, the tactics, the mitigations with a one-sentence summary, and each technique's name, tactics and mitigations | a version, tactics, techniques and mitigations are present; a technique names only tactics and mitigations that are listed |
| `internal/indicator/indicators.json` | indicator types and their regex patterns | every entry has a type and a pattern; every pattern compiles |
| `internal/structured/formats.json` | the extensions of each structured format, the field names that hold a command, and the HTML elements that hold a command, are kept verbatim or are dropped | the formats are `json`, `xml`, `html` in that order; extensions are lower-case, dotted and in one format; names are lower-case letters and digits, listed once, and an element is in one list |

All are embedded with `go:embed` and decoded strictly: an unknown field or trailing data is an
error.

`internal/render/readout.html.tmpl` is the page of the HTML report, its markup and its style. It
is embedded too, and `html/template` escapes every text that is written into it.

## 3. Reading evidence

The tool keeps no state: every run names its input directory with `-inputdir`. It writes to
standard output, standard error and the output folder, which is never inside the input directory.

A run uses every processor, and its output does not depend on how many there are: each piece of
work writes only its own result, and the results are taken in a fixed order.

- The files are analysed apart from one another, and what they hold is read while the timeline is
  built.
- A text of 16 KB or more is searched for each indicator pattern and each activity apart. A
  pattern whose matches cannot cross a line is searched in pieces of about 256 KB that end on a
  line break; `indicator` reads that from the pattern itself and searches the whole text otherwise.
- A pattern whose every match holds a fixed text, such as `://` or `@`, is tried only on the lines
  that hold it, when fewer than half of the lines do. The text is read from the pattern's literals.
- The saved files are made apart from one another. A table is written one row at a time, so its
  size does not add to the memory a run holds.
- A saved file is written as `<name>.part` and takes its name when every file is complete. A run
  that fails removes the parts, so the output folder holds no file half written.
- `-cores` sets how many processors a run uses, as a percentage of those of the machine, and
  `-memory` a limit on its memory, as a percentage of that of the machine. Without `-memory` the
  limit is 75 percent.
- The memory of the machine is `MemTotal` of `/proc/meminfo` on Linux, or the limit of the control
  group when that is less; `GlobalMemoryStatusEx` on Windows; `hw.memsize` on macOS. Elsewhere it
  is not known: no limit is set, and `-memory` is refused.
- The limit is the soft limit of the Go runtime: the collector frees memory sooner as the run
  nears it, and a run that must hold more still does. `GOMAXPROCS` and `GOMEMLIMIT` in the
  environment are kept when the options are not given.

- The input directory is opened as a root (`os.OpenRoot`) and every file is opened through it read-only, so
  no path leads outside the folder.
- Only regular files are listed. Symbolic links and special files are skipped without being
  opened. Hidden files are listed.
- A read takes a depth. At depth 0 only the files directly in the folder are listed and sub-folders
  are skipped. `report` reads at `inventory.MaxDepth`, 16 levels of sub-folder. Each
  sub-folder is opened through the same root. A symbolic link to a folder is not walked, so a walk
  cannot loop or leave the folder.
- A file's path is below the input directory and slash separated. Its role and file-name timestamp
  come from the last element only.
- A sub-folder below the depth, or one that cannot be read, is recorded in `Result.Skipped` and the
  verb reports it as an error after its output is written.
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
  the decoded text, which the trace and the exposure need; `report` uses it.

## 4. File-name timestamps

`nametime.Detect` tries a date and time, then a 10-digit Unix epoch between 1500000000 and
1999999999 (three more digits are read as milliseconds and dropped), then a date. Each rule looks
at its first match only, a stamp never touches another digit, and an impossible calendar date
abandons its rule. A date and time without `Z` is marked local: the name does not state its zone.

## 5. Structured outputs

The trace decodes an output whose extension `formats.json` claims before it looks for indicators
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
  case and every character but a letter or a digit ignored) or inside an HTML command element. A
  JSON list whose strings hold no space is one argument vector; otherwise each string is a command
  line.
- The command fields are those of Sysmon and Defender process events, and of Falco and auditd
  records on Linux: `proc.cmdline`, `proc.pcmdline` and `proctitle`.
- A command is parsed as PowerShell when it holds a `Verb-Noun` cmdlet or names `powershell` or
  `pwsh`, as a cmd.exe line when it holds a drive path, a UNC path, an `.exe`, a `%NAME%` or a
  slash switch, and as bash otherwise. Its tools, tactics and transforms fill the file's row of
  the trace. A structured output is not a turn and links no output.
- A JSON or XML file that is not well formed is read as plain text. HTML is decoded whatever its form.

## 6. Windows command lines

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

## 7. Shell command lines

`parse.ExtractBash` reads a shell script one statement at a time. The tool of a statement is its
first word that is not an assignment, an option or a wrapper such as `sudo`, `nohup`, `timeout`,
`doas` or `xargs`.

- A command that launches another is followed, four levels deep: the string after `-c` of `sh`,
  `bash`, `zsh`, `dash`, `ksh`, `ash` and `su`, the arguments of `eval`, the remote command of
  `ssh`, the command of `find -exec`, what follows `--` or the container name of `kubectl exec`,
  `docker exec` and `podman exec`, and the statements of `python -c`.
- A subshell `( ... )` and a group `{ ...; }` are read as the commands they hold, with or without
  a redirection after the closing bracket.
- The commands inside `$( ... )` and backticks are read. The substitution itself is no word of
  the outer command, so an address in it is not taken for a tool. `$(( ... ))` is arithmetic, and
  single quotes hold text.

## 8. Encoded payloads

`parse.Decoded` reads what a file carries encoded, and nothing is run: the argument of a
PowerShell `-EncodedCommand`, in any of its abbreviations, a Base64 literal handed to
`FromBase64String` or `b64decode`, and a Base64 literal that `echo`, `printf` or a here-string
feeds to `base64 -d`. A payload is kept when nearly all of it is printable text.

- The commands of an encoded command join the file's tools, and the text of every payload is
  searched for activities and indicators with the rest of the file. A payload piped from
  `base64 -d` into a shell is parsed as shell commands.
- Two layers are read: a payload that carries an encoded command is decoded once more.
- A payload over 1 MiB of Base64 is left alone, and a file yields at most 32 payloads.

## 9. Activities

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
- The report counts, for each activity, the lines that show it. A loop counts once: the tool
  does not run the script.
- An activity keeps the first 12 lines of each file that show it, each with its line number in the
  file and cut to 200 bytes. A command continued over lines is quoted joined, under the number of
  its first line.
- A subject is what a line acts on: a pattern with one group, tried on a line the activity
  matched, captures it and its label says what it is. `useradd -m svc` gives `account svc`, and
  `echo "$KEY" >> ~/.ssh/authorized_keys` gives `file ~/.ssh/authorized_keys`.
- A subject that is one variable is given the value the script sets it to, and keeps the name:
  `/tmp/tool ($F)`. `vars.Read` takes `NAME=value`, `export NAME=value`, `set NAME=value` and
  `$NAME = value`, the last assignment of a name, and the default of `${NAME:-default}`. A value
  that is computed is not read, and a variable that is never set is no subject.
- A name has a tactic in `tactics.json` only when the name alone says what the command does.
  `certutil`, `bitsadmin`, `reg`, `systemctl`, `chmod`, `crontab`, `history`, `tar`, `curl`,
  `wget`, `Invoke-WebRequest`, `Invoke-RestMethod` and the Python `requests` calls have none: the
  activity found on the line gives one.
- A write to a path is read from the command that makes it: a redirection, `tee`, `cp`, `mv`,
  `install` or `sed -i`. Reading the same path is a different activity or none.

| Activity | Tactics | ATT&CK |
| --- | --- | --- |
| `GlobalAdministratorAssignment` | PrivilegeEscalation, Persistence | T1098.003 |
| `RoleAssignment` | PrivilegeEscalation, Persistence | T1098.003 |
| `AppRoleAssignment` | Persistence, PrivilegeEscalation | T1098.003 |
| `AppCredentialAddition` | Persistence | T1098.001 |
| `TokenRequest` | InitialAccess | T1078.004 |
| `GraphDirectoryEnumeration` | Discovery | T1087.004, T1069.003 |
| `MailboxAccess` | Collection | T1114.002 |
| `TeamsMessageAccess` | Collection | T1213.005 |
| `SharePointEnumeration` | Collection | T1213.002 |
| `KeyVaultSecretRead` | CredentialAccess | T1555.006 |
| `KeyVaultKeyUnwrap` | CredentialAccess | T1555.006 |
| `KeyVaultKeyEnumeration` | Discovery | T1580 |
| `AzureResourceEnumeration` | Discovery | T1580 |
| `FileDownload` | CommandAndControl | T1105 |
| `FileUpload` | Exfiltration | T1048 |
| `DownloadAndExecute` | Execution, CommandAndControl | T1059.001, T1105 |
| `ReflectiveCodeLoading` | Stealth | T1620 |
| `NativeApiCall` | Execution, Stealth | T1106, T1055 |
| `RuntimeCompilation` | Stealth | T1027.004 |
| `ProcessStart` | Execution | T1059, T1047 |
| `NetworkSocket` | CommandAndControl | T1095 |
| `SignedBinaryProxyExecution` | Stealth, Execution | T1218, T1127 |
| `RunKeyPersistence` | Persistence | T1547.001 |
| `ScheduledTaskCreation` | Persistence, Execution | T1053.005 |
| `ServiceCreation` | Persistence, PrivilegeEscalation | T1543.003 |
| `EventLogClearing` | DefenseImpairment | T1685.005 |
| `LsassDump` | CredentialAccess | T1003.001 |
| `RegistryHiveDump` | CredentialAccess | T1003.002 |
| `RegistryQuery` | Discovery | T1012 |
| `CertificateExport` | CredentialAccess | T1649 |
| `AmsiBypass` | DefenseImpairment | T1685 |
| `DirectorySearch` | Discovery | T1087.002 |
| `ScheduledJobCreation` | Persistence, Execution | T1053.003, T1053.002, T1053.006 |
| `SystemdUnitCreation` | Persistence, PrivilegeEscalation | T1543.002 |
| `AccountCreation` | Persistence | T1136.001 |
| `SshKeyPersistence` | Persistence | T1098.004 |
| `ShellProfilePersistence` | Persistence | T1546.004 |
| `SudoersModification` | PrivilegeEscalation | T1548.003 |
| `SetuidBit` | PrivilegeEscalation | T1548.001 |
| `ContainerEscape` | PrivilegeEscalation | T1611 |
| `KernelModuleLoad` | Persistence, PrivilegeEscalation | T1547.006 |
| `DynamicLinkerHijack` | Stealth, Execution | T1574.006 |
| `SetuidFileSearch` | Discovery | T1083 |
| `ShadowFileRead` | CredentialAccess | T1003.008 |
| `PrivateKeyRead` | CredentialAccess | T1552.004 |
| `CredentialFileRead` | CredentialAccess | T1552.001 |
| `ShellHistoryRead` | CredentialAccess | T1552.003 |
| `CloudMetadataAccess` | CredentialAccess | T1552.005 |
| `ProcessMemoryDump` | CredentialAccess | T1003.007 |
| `ClusterSecretRead` | CredentialAccess | T1552.007 |
| `LogDeletion` | DefenseImpairment | T1685.006 |
| `HistoryClearing` | Stealth | T1070.003 |
| `HistoryDisabling` | DefenseImpairment | T1690 |
| `SecurityToolDisabling` | DefenseImpairment | T1685, T1685.004 |
| `FirewallDisabling` | DefenseImpairment | T1686 |
| `Timestomp` | Stealth | T1070.006 |
| `ReverseShell` | Execution, CommandAndControl | T1059.004, T1095 |
| `ArchiveCreation` | Collection | T1560.001 |
| `ServiceDiscovery` | Discovery | T1007 |
| `ShellDownloadAndExecute` | Execution, CommandAndControl | T1059.004, T1105 |

## 10. Watchlist

`-intelfile` names a watchlist of known attacker infrastructure, and `intel` matches the
indicators of every file against it.

- The file is a JSON array of entries or a STIX 2.1 bundle. From a bundle, every quoted literal
  that an equality compares in the pattern of an `indicator` object is one entry, attributed to
  the name of the indicator, or to its id when it has no name.
- An entry that is an address range matches every address inside it.
- A match gives the finding its attribution and the severity `high`, and counts under
  `intel hits` in the summary.

## 11. Exposure and targets

`exposure.Extract` reads the text of every file and names what it holds that an attacker can use.
The rules are those of `exposures.json`, and the classes are described in the
[output schema](02-Output-Schema.md).

- A text that is JSON is read by its fields: an object is one record, and a string that holds a
  command or a message is read as a line of its own. A text whose first line is a header that
  names a known field is read by its columns, each later line one record. Any other text is read
  line by line: every `KEY: value` and `KEY = value`, then the patterns.
- A field name is compared without case and punctuation. It is of a kind when it is one of the
  kind's keys or ends as one of its endings; the longest ending decides. `name` is a device only
  beside a field that says the row is a host.
- A pattern is tried only on a line that holds one of the texts it needs, and not on a line its
  `unless` matches. A line is searched to 8 KiB.
- A value must match the kind's `valid` expression and must not match its `reject`: a
  placeholder, a boolean and a bare number are no password. A hash is exempt from `reject`,
  because a crypt hash begins as a placeholder does.
- The email addresses, the IP addresses, the JSON web tokens, the AWS key identifiers and the
  private key headers come from the indicators of the trace. An address that follows `$` is a
  variable and a domain, and is left out.
- The files are read in the order of the timeline. A value is `collected` when the first file
  that holds it is an output and `used` when it is a script.
- A secret seen without an account is the same secret seen with one, so the two are one row.
- A line number is a line of the file. An indicator or an activity found in a decoded report or
  in a decoded payload has none.

The same pass gathers the targets: what the scripts name outright.

- A username, an email address, a device or an address read from a script is a target; so is a
  domain, which is of no kind in an output. A name that is one folder of a Windows path, after a
  single backslash, is not a domain; after two it is the host of a share. `exposures.json` says which kinds are listed and
  under what title.
- A target is `discovered` when a file that is not a script and stands earlier in the timeline
  holds the same value, and `prior` otherwise.
- Its script lines are quoted after every secret is known, so each is masked.

## 12. ARTEX intents

ARTEX runs each intent of its plan in a folder of its own, `tasks/<task>/i<number>`, with the
output of its commands in `cmd-output` below it, and names the worker's session
`exp<number>-worker-i<number>`. `intent.Table.Of` reads the intent from a path by the rules of
`paths.json`.

- The rules are tried in order: the run folder under `tasks`, then the session name, then any
  folder named `i` and a number. Within a rule the last match decides, the folder nearest the file.
- The last three folders of the path to the input folder count as part of each path, so a run
  folder that is read itself still names its intent and its task.
- `command` groups the steps of the timeline by intent. The period of an intent runs from its
  earliest file to its latest, by the time the timeline orders them with.
- The techniques of an intent are those of the activities its files show: the ATT&CK techniques
  of `activities.json` and the ATLAS techniques section 14 gives them.
- The intents are ordered by when they began; one without a time comes last.

## 13. Assessment

The report ends with what the findings mean and what to do about them. Impacts and remediation
come from data files, and `assess` holds no knowledge of its own. Mitigation comes from the
catalogue of section 14.

- An impact or an action applies when one of its triggers is in the evidence: an activity, the
  tactic of a tool that ran, a watchlist match, or an exposed value of a kind it names. The
  tactics an activity adds do not trigger anything: the activity is named directly, so a
  reflective load is not read as log clearing.
- The basis and the files of each row say why it is there, so a reader can check the claim.
- Each row names its targets and quotes its evidence: the subjects and the lines of its
  activities, the first command of each tool behind its tactics, and the exposed values of the
  kinds it names. A secret counts whether it was collected or used; a username, an email address,
  a device and an address count only when collected, because what the attacker brought is not
  what the environment lost. A mitigation names each activity it answers and its subjects.
- A line an activity quotes is not quoted again for the tool that ran on it.
- An impact lists up to five affected values of the indicator types it names, taken from the
  files that show it; an address is cut to its host.
- A test fails when an activity has no impact or no remediation, so a finding cannot be reported
  and then left out of the assessment.
- One impact is not found but assumed: the scripts were written by an AI agent, which is the
  premise of the tool. It applies whenever anything is found and stands for an ATLAS technique.
- A notable file is one whose activities, tool tactics or watchlist matches are of high severity.
  A watchlist match is `high`.

## 14. MITRE ATT&CK and MITRE ATLAS

`internal/mitre/catalogue.json` is written by `scripts/mitre.py` from the ATT&CK enterprise bundle
of `mitre-attack/attack-stix-data` and a v6 file of `mitre-atlas/atlas-data`. It holds ATT&CK 20.1
and ATLAS 2026.10. The licences of both stand beside it, and it carries identifiers, names and a
one-sentence summary of each mitigation, not the full text of either framework.

- A tactic of `tactics.json` names its ATT&CK tactic and its ATLAS tactic. ATT&CK 20 has no
  Defense Evasion: it has Stealth and Defense Impairment, and so does this table. ATLAS keeps
  Defense Evasion, and both map to it.
- An activity of `activities.json` names its ATT&CK techniques. A test fails when an activity
  claims a tactic that ATT&CK does not file one of its techniques under.
- An activity's ATLAS techniques are those it names and those whose ATT&CK reference in ATLAS is
  one of its ATT&CK techniques or the technique that one is a part of.
- The mitigation rows of the report are not written here. For the techniques found, the
  catalogue gives the mitigations each framework links to them; a row is one mitigation, the
  techniques found that it addresses, and the activities and files that showed them.

## 15. Fixtures

`internal/evidencetest/testdata/bash` and `powershell` are the evidence folders of the
AgentScriptTrace golden test in the VelociSacci repository (`tests/golden/fixtures/`), copied byte
for byte. They hold CRLF, UTF-16, byte-order-mark and binary files on purpose.

`entra`, `lolbin` and `linux` belong to this repository. `entra` is an agent's run against Entra ID,
Microsoft Graph and Azure Key Vault in bash, PowerShell and Python, with a JSON Lines log; it shows
the cloud activities of `activities.json` except the plain role assignment. `lolbin` is a run on a
Windows host with living-off-the-land binaries and .NET: six PowerShell scripts, a batch file, C#
source, an MSBuild project and a process-creation log, on documentation addresses. `linux` is a
run on a Linux host: six shell scripts and a Python script that survey it, read credentials, raise
privilege, keep access, reduce the record and stage data, with their outputs and an audit log in
the field names of Falco, auditd and ECS. Its outputs hold accounts, a hash, a password, a token,
hosts and addresses, all made up, for the exposure to find. Its lines are fragments on variables
and documentation addresses, and no script in it works as written.

- `.gitattributes` marks every `testdata` path `-text`, so a checkout never converts them.
- `.gitignore`, `.editorconfig`, `.yamllint`, `.gitleaks.toml` and the fixer hooks leave `testdata` alone.
- A checkout does not keep modified times, so `<fixture>.times.json` states one per file and
  `evidencetest.Copy` applies it. Each is three seconds after the file-name timestamp, so the two
  never coincide in a golden file.
