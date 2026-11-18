# Changelog

All notable changes to this project are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A **Tactics** section, after the summary and before the timeline: each tactic the scripts
  show, most severe first, with its ATT&CK and ATLAS identifiers and the scripts that show it.
- A secret is linked to whose it is and what it is used against. One that no rule gives an
  account is of the one account its line names, or of its one application: the password of
  `sshpass -p`, of `--password`, of `/p:` and of a secure string beside a credential. A JSON web
  token is of the account its claims name. A secret with no known service is for the audience
  of a token, or for the one host its line names: `password of admin, dc01.corp.local`. The
  name and password of basic authentication are read out of its base64, and those of
  `curl -u`, of `-U name%password`, of `net user ... /add`, of `chpasswd`, of `ldapsearch -D ...
  -w` and of `domain/name:password@host` are read as well.
- An encoded secret is written decoded in the report: a JSON web token as its claims, base64
  that holds text as the text, a JSON document in base64 as its members, a key block as its type
  and fingerprint. `exposure.csv` holds the value as it stands and a `decoded` column beside it.
  A value that is not text when decoded is written as it stands.
- An impact, an action and a mitigation list the exposed accounts and credentials they concern,
  under `exposed`: every one of the kinds the entry is about, the credentials in the files that
  show the entry and the accounts on the lines that show it. `report.json` has an `exposed`
  column that holds every one.
- The tasks among the targets are listed with the task name and what the task runs. A task name
  in single quotes and one registered through the task service are read.
- The resources among the targets are listed with the activity first and the resource after
  it, under the columns `acted on by` and `resource`.
- The passwords and secrets of the exposure are listed under the columns `what`, `seen`,
  `value`, `found in`: what a secret is and whose, before the secret itself.
- A watchlist match is named in the block of its intent or its period.

### Changed

- The timeline is one section of blocks: a block for each ARTEX intent where the files name
  intents, and a block for each period of the same tactics where none does. The table of
  periods and the separate `intents` section are gone; `intents.csv` is unchanged. A block
  whose files show no technique says `no MITRE ATT&CK technique identified`.
- The findings are the activities. The tactics have their own section, and the indicators are
  in `findings.json` and counted in the summary; the report lists none.
- An impact, an action and a mitigation no longer quote commands or name scripts and what a
  command acts on: the findings quote each command once. `report.json` keeps the `targets` and
  the `evidence` of each.
- One secret of one account is one row of the exposure, which names every host the secret is
  used against, under either way of writing the account, `svc` and `svc@corp.example`. A secret
  named under two forms is one row.
- An account that is both a username and an email address is listed as the address. A login to
  a host, `scp file deploy@bastion01.corp.internal:`, is a username and a device and no longer
  an email address.
- A username given to a command as an identifier, as a service principal is, is an application.
- Archive creation covers 7-Zip under each of its names and with a path, `rar`, `gzip`, `bzip2`,
  `zstd`, a dump piped through a compressor, `makecab`, `Compress-7Zip`, the .NET `ZipFile`
  class and the archive calls of Python, and names archives of any of their extensions. An
  archiver named in a sentence, or at the end of a file name, is no archive.

### Removed

- The **Notable files** section and its rows of `report.json`: the tactics and the findings
  name the files.
- The indicators group of the findings in the report.
- Usernames among the targets: `targeted.json` and the Targeted section hold the email
  addresses, the hostnames and the IP addresses the scripts name. The exposure holds the
  usernames.

### Fixed

- A username is no longer read from a sentence that follows a field name, as `verify` was from
  `# Check user: verify the account exists` and `Mon` from `Last login: Mon Oct 20`. Neither
  is a date, a version, an identifier, a hash, a file name, a placeholder, the system account,
  a storage account, the word after `-u` of a command that takes no account, a line break
  written `\n`, or a folder in a path. The accounts of `id`, `whoami`, `who`, `sudo -l`, a rule
  of `sudo`, `useradd`, `net user`, `net localgroup`, the account cmdlets, `/u:` and an ARN of
  AWS are read.
- A line of `=` signs, of dashes or of any signs alone is no secret and no key, so a heading
  such as `===== Access Token =====` leaves nothing in the exposure. A sentence after a field
  name, `password: must be at least 8 characters`, is no password, and `NOPASSWD` of a rule of
  `sudo` names none.
- The hostnames among the targets leave out the hosts of vendors that any script reaches for:
  `www.google.com`, `graph.microsoft.com`, `login.microsoftonline.com`, package registries,
  the mirrors of distributions and certificate authorities. A host a tenant names under a
  vendor's domain, such as `contoso.sharepoint.com`, stays.
- An archive written as the last word of an upload, `curl -T docs.zip https://host/docs.zip`,
  was read as a `zip` command.

## [0.6.0] - 2026-11-18

### Added

- `-start <time>` and `-stop <time>` set a window of time on what a run reads. `-start` alone
  looks forward from its time and `-stop` alone looks back from it. A file whose time is
  outside the window is not opened, so it is not hashed, not analysed and in no saved file.
  The time of a file is the one the timeline places it at: the time in its name, or else when
  it was last modified. A time is a day or a day and a time, UTC unless it names a zone; a day
  alone is the whole day, and a file named by a day alone is in the window when any part of
  that day is.
- The summary of a run with a window has the row `left out`, with the number of files outside it
  and what the window left out, on the screen, in the saved reports and in `report.json`.

- `files.csv` has the column `path`: the whole path of each file on the machine of the run.
- A finding in `findings.json` has `first` and `last`, the times of the earliest and the latest
  file that shows it.
- `indicators.json` says what a match of a type must not follow, `not_preceded_by`, as it says
  what must not follow it. `sift.Backwards` turns that expression round, so it is run from the
  match backwards: from one place, not from each of the bytes before the match.
- A file belongs to the ARTEX intent its own name holds: `i` and a number with no letter and no
  digit before or after them, as in `i1042_scan.sh` and `cmd-i1042.stdout.txt`. The name of a
  file decides before the folder it lies in, and the intent owns the techniques of each of its
  files.
- A file is read with its creation time, where its file system records one. `files.csv` has the
  column `created`.
- The table of the intents has `timed_by`: whether the period of an intent is read from
  creation times, from the times of the timeline, or from both.
- The exposure names tenants, SSH keys, API keys, applications and cloud resources, beside the
  passwords, usernames, email addresses, devices and addresses. A tenant is a directory
  identifier or a domain of `onmicrosoft.com`. An SSH key is a public key by its fingerprint,
  the header of a private key, or the key file `ssh -i` is given, each with the user and the
  host the evidence gives it. An API key is a value in the form a service gives its keys, or
  under a field that names a key.
- A value of the exposure has a `service`: what it gives access to, such as `Microsoft 365`,
  `Google Cloud`, `AWS`, `GitHub` or `OpenAI`, and the host of an SSH key. It is read from the
  form of the value, from the issuer of a JSON web token and from the name of the field.
  `exposure.csv` has the column `service`, and `exposures.json` lists the services.
- The Exposure section lists what is of Microsoft 365 and what is of Google Cloud in a group of
  each, whatever its kind.

### Changed

- The time of a file has one definition, `evidence.File.Time`, which the timeline and the
  reading share. `inventory.Scope` says how much of a folder is read: the depth, the
  window and what is told of each file.
- The files and the exposure are saved as CSV, `files.csv` and `exposure.csv`, in place of
  `files.json` and `exposure.json`: a line of keys and a line per row. A value that does not
  apply is an empty cell, and a text that a spreadsheet would read as a formula follows an
  apostrophe.
- The `evidence` of a finding in `findings.json` is an array with one object per line: the
  `time` of its file, the `file`, the `line` and the `text`. It was one string.
- `commands.json` names the format of each saved table, `json` or `csv`.
- An API key under a field whose name ends as `apikey`, `secretkey` or `accesskey` does, and
  an AWS key, is of the kind `apikey` and no longer of `password`. The header of a private key
  of SSH is of the kind `sshkey`.
- A value of the exposure is folded into the same value of which the evidence says more, its
  account or its service, where a secret was folded only into one with an account.
- The Intents section is the Intent timeline: a line of blocks, one for each intent, in the
  order the intents began. A block names the intent and the period it ran for, and lists each
  of its ATT&CK and ATLAS techniques by its identifier and its name, a sub-technique after the
  technique it is part of. Every intent has its block, however many there are.
- The intents are saved as CSV, `intents.csv`, in place of `intents.json`. A row begins as the
  table of the intents does, with `from`, `until`, `intent`, `attack`, `atlas` and `files`, and
  holds every file of the intent; `task`, `seconds`, `timed_by`, `severity`, `tactics` and
  `activities` follow.
- An intent runs from the first of its files to be created until the last. It ran from the
  earliest to the latest time of the timeline: the timestamp in a file name, or else the
  modified time. A file whose creation time is after its last change is a copy, made when it was
  copied, and keeps the time of the timeline, as does a file with no creation time; the last
  line of the section counts those files.

### Removed

- `-secrets`. A secret is written as it stands in the evidence, on the screen and in every
  saved file: in the exposure, in a command quoted as evidence, in a target and among the
  indicators. It was masked unless `-secrets shown` was given.

### Fixed

- The release workflow checks `intents.csv`, the file a run saves, before it publishes. It
  looked for `intents.json`, which is saved no longer, so no release could be cut.
- A version number is not reported as an IPv4 address. Four numbers are an address only when
  none has a leading zero and the first is not 0, `0.0.0.0` apart, and they are left out where
  the text says they are a version: after `version`, `ver`, `build`, a comparison, `^`, `~`, a
  package name and a hyphen or the name of a browser, beside a fifth number, and before a
  suffix such as `-rc1` or `-1ubuntu2`. `0.1.5.3` and `Chrome/120.0.0.0` are no longer
  indicators.

## [0.5.5] - 2026-11-17

### Changed

- The Timeline section tells what was done, not what files there are. An entry is a period: the
  files, one after another, that show no tactic the first of them does not, with its first and
  last time, the number of its files, its tactics, activities, tools, watchlist matches and
  intents. A file that shows no tactic and no watchlist match is counted in the last line and
  not listed, whatever its role. Of more than 40 periods the first 20 and the last 20 are shown.
  A folder of 2,198 files whose timeline was 6,836 lines is told in 14 periods. `trace.json`
  holds every file, as it did.

### Added

- A run says what it is doing. On a terminal one line on standard error names the stage, of
  five, how many of the files or of the saved files are done, how long the stage has lasted and
  the file the run has been at for longest, and is taken off before the report is printed.
- `-progress shown|hidden`. `hidden` says nothing on a terminal; `shown` writes a line when a
  stage begins and every ten seconds while it lasts where standard error is not a terminal,
  such as a log file. Without it nothing is written there, and standard output is unchanged.
- `internal/progress`, which writes the line.

### Fixed

- A run writes nothing outside its output folder. When the folder already held a symbolic or a
  hard link named as a saved file is while it is written, such as `findings.json.part`, the
  file was written through the link, into whatever it led to: a file elsewhere, or one of the
  evidence. The output folder is opened as a root and each file is made new in it, so the link
  is replaced and what it led to is left alone. Before 0.5.4 the same held of a link named as
  the saved file itself, such as `findings.json`.
- A save that fails while the files are given their names removes the parts that are left.

## [0.5.4] - 2026-11-17

### Changed

- The saved tables are written one row at a time instead of being built whole in memory, and
  each saved file is written as `<name>.part` and renamed when every file is complete. The bytes
  of every saved file are unchanged, and a run on a large folder holds less than half the memory
  it did.
- An expression is run only where a match can be. `internal/sift` reads each expression once, when
  its table is loaded, for the texts every match holds and the bytes a match is made of, and a
  text, a line or a run of bytes that cannot hold a match is left alone. The indicators, the
  activities, the exposure patterns and pairs, the variables and the encoded payloads are all
  searched this way. What a run finds is unchanged, and a run on a large folder takes less than
  half the time it did.
- The literals of all the activity patterns are looked for in one pass over a text, and each
  pattern then reads the lines of its own. A pattern whose literal holds a line break is refused
  when `activities.json` is loaded: it matches no line.

### Fixed

- An activity whose line writes `s` as the long s or `k` as the Kelvin sign is found. The
  expressions always matched such a line, and the search for their literals passed it over.

## [0.5.3] - 2026-11-17

### Changed

- The timeline and the `trace.json` `time` field write every instant as one ISO-8601 UTC stamp,
  whether it comes from the file name or the modified time. A file-name timestamp is read as UTC,
  so a time column no longer mixes a bare token or a Unix epoch with an ISO instant. The intent
  `first` and `last` fields follow; the file name's own token stays in the `file` class `name_time`.

### Added

- The Targeted section lists every entity an activity acted on, grouped by label: accounts,
  hosts, files, services, URLs and others. Each entry names the value, the activities that
  touched it and the evidence lines, so a responder sees at a glance which entities were
  affected and what happened to each.
- `docs/artex/records.md`, recording the files ARTEX writes about its own work: where the intent
  number comes from, the data folder, the formats of its transcripts, spilled output and context
  archives, its session names, the vocabulary of its graph and the tools that write results back,
  from reading twelve checkouts of ARTEX and its forks.

### Fixed

- The overflow line under an impact, a remediation, a mitigation, a finding activity or a targeted
  value names the saved file that holds the lines it omits, such as `report.json` or the saved
  findings, not "the saved report", which keeps the same limit and never held them.
- An activity and a tool citation for the same command on the same line no longer both appear in
  impact and remediation evidence. The duplicate is suppressed by keying on the file, line and
  bare command text.
- A section whose groups are all empty no longer appears in the report. A fixture without ARTEX
  intents no longer prints "Intents: none".
- The "Commands generated by an AI agent" impact is now low severity, not medium. It no longer
  floors the verdict of every run to at least medium.
- An unresolved shell variable in a subject pattern (such as `$JOB` or `$PORT`) is kept as a
  target instead of being silently dropped. Remediation evidence now shows what a command acted on
  even when the script never sets the variable.
- `docs/artex/findings.md` states that `task-%d-exp-%d-worker-i%d` is the key of the side
  questions an operator asks about a worker, and that `noa` is the folder where the SDK archives
  the context of a conversation.

## [0.5.2] - 2026-11-17

### Added

- `-cores <percent>` sets how much of the processors of the machine a run may use, and
  `-memory <percent>` how much of its memory the run tries to stay within. Each is a percentage
  from 1 to 100 of the machine the run is on. Neither changes anything the run writes.
- A run tries to stay within 75 percent of the memory of the machine when `-memory` is not given.
- `internal/device`, which reads the processors and the memory of the machine on Linux, Windows
  and macOS.
- `docs/artex/report.md` and `docs/artex/findings.md`, recording which markers survive a fork of
  ARTEX and which are specific to one build, from reading twelve checkouts of ARTEX and its forks.

### Changed

- A run uses every processor. The files are analysed apart from one another; a large text is
  searched for each indicator pattern and each activity apart, and in pieces cut at line breaks
  where a pattern's matches stay in a line; the saved files are made apart from one another. The
  output is byte for byte what one processor gives.
- An indicator pattern whose every match holds a fixed text, such as `://` or `@`, is tried only
  on the lines that hold it.
- The input directory is read on every processor, not one file after another.
- The report is assembled in time that grows with the evidence, not with its square. The files
  behind an impact, an action, a finding and an output are gathered through a set, and the affected
  values of an impact are deduplicated through one. A folder of 24,000 files that did not finish in
  two minutes is reported in about forty seconds, and one of 6,000 files in half the time it took.
- A 50 MB log that took 59 seconds takes 15 on four processors and 49 on one. The peak of memory
  for that log rises from about 610 MB to about 810 MB.

## [0.5.1] - 2026-11-17

### Fixed

- An output folder on another drive than the input folder is no longer refused as being inside
  it. Two paths on two Windows volumes could not be compared, and that was read as "inside", so
  `-outdir` on another drive failed and the default output folder was never the current directory.
- An input folder on a volume that cannot resolve its links, such as some mounted disk images, is
  compared by its path and by the folder it is, and is no longer refused.
- A drive that is read whole, such as `-inputdir E:\`, gives the output folder the letter of the
  drive, `slopmop-E`; it had no name to give.

## [0.5.0] - 2026-11-17

### Added

- The `intents` section of `report`: a timeline of the ARTEX intents. An intent is read from its
  run folder, `tasks/<task>/i<number>`, or from the session name `exp<number>-worker-i<number>`.
  Each row gives the first and last time of its files and the span between them, its tactics, its
  ATT&CK techniques and its ATLAS techniques, and each activity with the techniques it brings.
- `intents.json` holds the `intent` class, one row per intent. A run saves ten files.
- The `trace` class has an `intent` key, and a step of the timeline names its intent.
- The summary counts the intents when a file belongs to one.
- `internal/intent` and its data file `paths.json`, which declares the rules that find an intent
  in a path.

## [0.4.1] - 2026-11-17

### Added

- `report` saves the report as Markdown and as HTML beside the plain text: `report.md` and
  `report.html`, each with every section. A run saves nine files.
- `report.md` writes a group of entries as a table or as a list, and every value and line of
  evidence as a code span, so a viewer shows it as written and makes no link of it.
- `report.html` is one page that needs no other file. It follows the light or dark setting of the
  browser, holds no script and no link out, and its content security policy loads nothing.
- The tables of the Markdown and HTML reports name their columns.

### Changed

- `commands.json` declares the saved report as a list of formats, each with its file name.
- The README states the one command, the nine sections and the seven saved files in tables, and
  leaves the packages to the architecture document.
- The architecture document follows the order of the pipeline, gives the watchlist a section of
  its own, separates the targets from the exposure and shows the import graph as it is.
- The output schema groups the rules of the report under layout, sections, places and limits.

### Fixed

- A folder of a Windows path that reads as a domain, such as `Microsoft.NET` in
  `C:\Windows\Microsoft.NET\Framework64`, is no targeted hostname.
- The release workflow runs the binary it publishes with the grammar of 0.4.0: `--help`, then
  `report`, and checks the saved `trace.json` and `report.txt`.

## [0.4.0] - 2026-11-17

### Added

- The readout of `report`: plain lines for reading, with a verdict line, `[x]`, `[!]` and `[i]`
  marks for high, medium and low, entries aligned in columns and detail lines under them. Colour
  is used only on a terminal, never with `NO_COLOR`, and on Windows only inside Windows Terminal.
- `report` saves every run to an output folder: `report.txt` with every section, and
  `files.json`, `trace.json`, `findings.json`, `targeted.json`, `exposure.json` and `report.json`,
  one per class. The folder is
  `slopmop-<name>` in the current directory, beside the input folder when the current directory
  is inside it, or the one `-outdir <folder>` names. An output folder inside the input folder is
  refused.
- The exposure: a section of the report and `exposure.json` list the usernames, email addresses,
  passwords and other secrets, devices and IP addresses the files hold. Each value says whether
  the scripts collected it or the attacker brought it, where it stands by file and line, and, for
  a secret, what it is and whose. `exposures.json` declares every rule.
- The targeted section: the usernames, IP addresses, hostnames and email addresses that the
  scripts name outright, saved as `targeted.json`. Each says whether the attacker knew it
  beforehand (`prior`) or an earlier output of the run held it (`discovered`, with that output),
  whether an address is private or public, and quotes the script lines that name it.
- A secret is masked wherever it would stand: in the exposure, in a command quoted as evidence,
  in a target and among the indicators. `-secrets shown` writes each as it stands.
- An impact and an action name their targets and quote their evidence: the account, file, unit,
  host or address each activity acted on, the lines that show it with their file and line, the
  first command of each tool behind a tactic, and the exposed values they concern. A mitigation
  carries the framework's own sentence and names each activity it answers with what that activity
  acted on. `report.json` gains the columns `targets` and `evidence`.
- An activity keeps the lines that show it and the subjects of each line; `activities.json`
  declares the subjects. A finding quotes its lines, and `findings.json` gains `evidence`. A
  variable the script sets is shown with its value.
- An exposed secret brings in `Credentials exposed` and `Rotate what was read` by itself, and a
  collected username, email address, device or address brings in `Environment mapped`.
- Packages `internal/exposure` and `internal/vars`.
- `internal/command/commands.json` declares the usage line, the options, the verbs with their
  sections and saved files, and the columns of each class.
- Linux activities, each with its ATT&CK techniques, an impact and a remediation:
  `ScheduledJobCreation`, `SystemdUnitCreation`, `AccountCreation`, `SshKeyPersistence`,
  `ShellProfilePersistence`, `KernelModuleLoad`, `DynamicLinkerHijack`, `SudoersModification`,
  `SetuidBit`, `ContainerEscape`, `SetuidFileSearch`, `ServiceDiscovery`, `ShadowFileRead`,
  `PrivateKeyRead`, `CredentialFileRead`, `ShellHistoryRead`, `CloudMetadataAccess`,
  `ProcessMemoryDump`, `ClusterSecretRead`, `LogDeletion`, `HistoryClearing`, `HistoryDisabling`,
  `SecurityToolDisabling`, `FirewallDisabling`, `Timestomp`, `ReverseShell`, `ArchiveCreation`
  and `ShellDownloadAndExecute`. `AccountCreation`, `FirewallDisabling`, `ServiceDiscovery` and
  `ArchiveCreation` also recognise the Windows commands.
- The shell parser follows a command that launches another, four levels deep: the string after
  `-c` of a shell or `su`, `eval`, the remote command of `ssh`, `find -exec`, `kubectl exec`,
  `docker exec`, `podman exec` and `python -c`.
- The shell parser reads the commands inside `$( ... )`, backticks, a subshell and a group.
- Encoded payloads: a Base64 literal that `echo`, `printf` or a here-string feeds to `base64 -d`,
  and one handed to the Python `b64decode`. A payload piped on into a shell is parsed as shell
  commands.
- Command fields of Falco and auditd records in a structured output: `proc.cmdline`,
  `proc.pcmdline` and `proctitle`.
- Wrappers `doas`, `setsid`, `watch` and `ionice`: the command behind one is the tool.
- Remediations `Undo privilege changes on hosts` and `Restore security tooling`.
- Fixture `linux`: a run on a Linux host in shell and Python, with an audit log and outputs that
  hold accounts, a hash, a password, a token and hosts.

### Changed

- The grammar is `slopmop -inputdir <folder> VERB [section ...] [options]`, and `report` is the
  one verb: `slopmop -inputdir <folder> report impact remediation`. It reads the folder and its
  sub-folders once. A bare word after the verb names a section, and no word means every section.
- An option is written with one dash or two and always takes a value: `-inputdir`, `-intelfile`,
  `-outdir` and `-secrets`.
- Help follows the command line. Asked for at any point, it prints what the line holds so far,
  what is still needed, what can be added, a `next:` line for the help of the next point and,
  once nothing is missing, the `run:` line. `slopmop -inputdir --help` explains the option,
  `slopmop -inputdir <folder> --help` lists the verbs, `slopmop -inputdir <folder> report --help`
  lists the sections, and with a section named it lists those chosen and those left.
- A notable file is one with a finding of high severity.
- The readout lists the first 40 indicators and says how many more the saved findings hold.
- `systemctl`, `chmod`, `crontab`, `history` and `tar` have no tactic by name. The activity on the
  line gives one, so `systemctl status`, `crontab -l` and `tar x` no longer claim Persistence,
  Stealth or Collection.
- `curl` or `wget` piped to a shell is `ShellDownloadAndExecute`, with ATT&CK T1059.004, and no
  longer `DownloadAndExecute`, which names the PowerShell technique.
- The impacts `Privileged access obtained`, `Persistence established` and `Data collected` and the
  remediation `Remove persistence` are worded to cover a host as well as a tenant.
- The activity table of `docs/03-Architecture.md` states the ATT&CK techniques of each activity
  and the tactics of ATT&CK 20.

### Removed

- The grammar `slopmop NOUN VERB`, the nouns `file`, `trace`, `finding`, `report` and `campaign`,
  the verb `list`, and their aliases. The saved JSON files carry what `file list`, `trace list`,
  `finding list` and `report list` printed.
- Selectors, the output flags `-o`, `-q`, `--no-headers` and `--tz`, the switch `--recursive` and
  the param `--severity`.
- `nouns.json`.

### Fixed

- The first command of a subshell was recorded with its bracket, as `(crontab`, and the last
  command of a group with its semicolon.
- A command whose argument is a substitution, such as `bash -c "$(curl ...)"`, took the tail of
  the address inside it for a tool.

## [0.3.0] - 2026-11-16

### Added

- `report list` lists the notable files after the counts: each script, output or other file that
  holds a finding at or above `--severity` (`high` unless given), with what was found in it and the
  files it is linked to.
- `report list` gives an impact report: what the findings mean, such as credentials exposed,
  persistence established or defences impaired, with the files that show it and the hosts or
  addresses affected.
- `report list` gives a remediation report: the actions that undo what was found, each with a
  priority.
- `report list` gives a mitigation report mapped to MITRE: for the techniques found, the
  mitigations MITRE ATT&CK and MITRE ATLAS link to them, each with the framework's own summary,
  the techniques it addresses and the activities and files that showed them.
- MITRE ATT&CK and MITRE ATLAS identifiers: every tactic names its tactic in both frameworks and
  every activity its techniques. `finding list` and `report list` show them in the ATTACK and
  ATLAS columns of the wide view.
- Package `internal/mitre` and `catalogue.json`: the identifiers, names and mitigation links of
  ATT&CK 20.1 and ATLAS 2026.10, written by `scripts/mitre.py` from the upstream files. The
  licences of both are beside it.
- Tactic `Impact`, and the impact `Commands generated by an AI agent`, which stands for the ATLAS
  technique for generated commands.
- Selectors `-summary`, `-files`, `-impact`, `-remediation` and `-mitigation` for `report list`.
- Package `internal/assess` and its data files `impacts.json` and `actions.json`, embedded and
  validated at load. A test fails when an activity has no impact or no remediation, or claims a
  tactic that ATT&CK does not give its techniques.
- Activities recognise an upload by `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod` and
  the Python `requests` calls, a download by `wget` and `urlretrieve`, and `curl` piped to a shell.
- `cli.Usagef`, the usage error of a verb that rejects the value of a param.

### Changed

- The tactic `DefenseEvasion` is now two, as in ATT&CK 20: `Stealth` (removing or hiding traces,
  compiling after delivery) and `DefenseImpairment` (clearing logs, switching off tooling).
  `bcdedit`, `vssadmin` and `wbadmin` are `Impact`.
- `SharePointEnumeration` is Collection alone, and `ReflectiveCodeLoading` and
  `RuntimeCompilation` are Stealth alone, as ATT&CK files their techniques.
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
