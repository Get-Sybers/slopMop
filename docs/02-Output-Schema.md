# Output schema

What `report` prints, the files it saves, and the classes those files hold.

## 1. The report

`slopmop -inputdir <folder> report` prints plain lines for reading.

```text
$ slopmop -inputdir case42/ai_workdir report summary exposure impact
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

Exposure   (collected: first seen in an output; used: first seen in a script; a secret is masked)
  Usernames (2)
    [!] MSOL_0a1b2c3d4e5f  collected  sync_10.20.1.17_retry_20250302_090930.txt:9
    [!] svc_backup         used       20250302_090900_step03_sync_retry.ps1:3, 20250302_090900_step03_sync_retry.ps1:4
  Devices (3)
    [i] AADC01  collected  hosts_20250302_090030.csv:3
    [i] CA01    collected  hosts_20250302_090030.csv:4
    [i] DC01    collected  hosts_20250302_090030.csv:2
  IP addresses (3)
    [i] 10.20.1.17  collected  hosts_20250302_090030.csv:3, sync_10.20.1.17_20250302_090530.txt:1, 20250302_090900_step03_sync_retry.ps1:2
    [i] 10.20.1.23  collected  hosts_20250302_090030.csv:4, 20250302_091500_step04_certs.ps1:2
    [i] 10.20.1.5   collected  hosts_20250302_090030.csv:2, 20250302_091500_step04_certs.ps1:2

Impact
  [x] Credentials exposed
      Secrets, keys, certificates or stored passwords were read. Treat them as known to the attacker.
      targets  file ca01_20250302_092210.cer
      what     CertificateExport: Export-Certificate -Cert $Store -FilePath ca01_20250302_092210.cer | Out-Null (20250302_092200_step05_export.ps1:5)
               get-credential: $Cred = Get-Credential -UserName $User -Message 'sync server' (20250302_090900_step03_sync_retry.ps1:4)
               new-selfsignedcertificate: $new = New-SelfSignedCertificate -DnsName $Dns -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1) (20250302_092200_step05_export.ps1:6)
      basis    CertificateExport, CredentialAccess tools

[x] HIGH - 4 impacts: 2 high, 1 medium, 1 low
-> saved to slopmop-ai_workdir: report.txt, report.md, report.html, files.json, trace.json, findings.json, targeted.json, exposure.json, report.json
-> one section: slopmop -inputdir <folder> report impact
```

### Layout

- Line 1 names the verb and the folder. Line 2 is the verdict: the highest severity among the
  impacts and the count at each, or `[ok] NOTHING FOUND in <n> files`. The verdict is repeated at
  the end when more than one section prints, where a terminal leaves the reader.
- A mark gives a severity or a priority: `[x]` high, `[!]` medium, `[i]` low. The marks are ASCII.
- A section is its title, then its entries indented two spaces. A section with no entry prints
  `none`.
- An entry is one line of cells, aligned with the entries around it. A column is padded to at
  most 60 characters; a longer cell runs past it.
- Detail lines stand indented under an entry, each with a label. Lines that share a label stand
  under it, and the label is written once.
- Times are UTC.
- Colour is used only when standard output is a terminal, `NO_COLOR` is unset and `TERM` is not
  `dumb`; on Windows, only inside Windows Terminal. A file or a pipe receives no colour code.

### Sections

| Section | Entry | Detail lines |
| --- | --- | --- |
| Summary | a count and its breakdown; with a window of time, the row `left out`: the files outside it and what the window left out | none |
| Timeline | a period: its first time, its last, the number of its files, its tactics | `intent`, `activities`, `tools`, `watchlist`, `files` |
| Intents | the intent, the first and the last time of its files, the span between them, the number of files | `task`; `tactics`; `attack`: the ATT&CK techniques; `atlas`: the ATLAS techniques; `found`: each activity with its ATT&CK techniques and the ATLAS techniques that go with them; `files` |
| Findings, activities | activity, lines, tactics, techniques | `what`: the lines that show it, each with its place |
| Findings, indicators | type, value, files | `watchlist`: the attributions |
| Findings, tactics | tactic, its ATT&CK and ATLAS identifiers, files | none |
| Notable files | role, file | `found`, `linked` |
| Targeted, a group per kind | the value, for an address whether it is private or public, whether it is prior or discovered, the places in the scripts | `from`: the output that held a discovered value first; `what`: the script lines that name it |
| Exposure, a group per kind | the value, whether it was collected or used, the places; a secret also says what it is and whose | none |
| Impact | the impact | its statement; `targets`: what it concerns; `what`: the lines that show it; `basis`; `files` when no line is quoted |
| Remediation | the action | its text; `targets`: what to act on; `what`; `basis`; `files` when no line is quoted |
| Mitigation | the mitigation, the techniques found that it addresses | the framework's own sentence; `for`: each activity it answers and what that activity acted on |

The values are those of the classes of section 6: a period of the timeline is drawn from the
`trace` rows of its files, an intent entry is an `intent` row, a finding
entry is a `finding` row, a targeted entry is a `targeted` row, an exposure entry is an `exposure`
row and the other sections are `report` rows. An activity's `lines` is its count in the summary of
the `report` class.

### Timeline

The timeline tells what was done, in the order of time. An entry is a period, not a file: a
folder of a thousand files is read in the periods it falls into.

- A file is in a period when it shows a tactic, of a tool that ran in it or of an activity, or a
  watchlist match. A file that shows neither is in none, whatever its role, and ends none. The
  last line of the section counts those files.
- A period begins with a file that shows a tactic the first file of the period before did not,
  and holds the files after it for as long as each shows no other tactic. A run that turns from
  discovery to credential access begins a period there, and a file of discovery alone inside it
  does not end it.
- `until` is `-` when the period is one instant. The tactics are those of the first file, in the
  order of `tactics.json`. `activities`, `tools`, `watchlist` and `intent` name what the files
  of the period show, each once, in the order it is first shown.
- The saved `trace.json` holds every file with what it shows; the timeline leaves none of that
  out of it.

### Places, targets and evidence

- A place in the evidence is written `file:line`, the line counted from 1 in the file as it
  stands. The line is left out where there is none: in a JSON, XML or HTML output, which is read
  by its values, and in a payload that was decoded out of a file.
- A target is what a line acts on, with its kind: `account svc`, `unit sync.service`,
  `file /etc/sudoers.d/svc`, `url http://203.0.113.40/s.sh`. A variable the script sets is given
  its value and keeps its name: `file /tmp/tool ($F)`. A variable the script never sets is no
  target. An impact and an action also list the exposed values they concern:
  `password of app_rw`, `username deploy`.
- A line of evidence is the command as the file holds it, cut to 200 bytes, with its place. Under
  an impact or an action it begins with the activity or the tool it is evidence of:
  `AccountCreation: useradd -m -s /bin/bash svc (20261022_091500_step04_persist.sh:7)`.

### Limits

A long list is cut on the screen and in the saved report alike; the cut entry names the JSON file
that holds every line it omits, because the screen and the saved report share one limit.

| List | Shown |
| --- | --- |
| the files of an entry | the first 3: `a.sh, b.sh, c.sh and 4 more` |
| the periods of the timeline | the first 20 and the last 20, with the number left out between them |
| the activities, the tools and the intents of a period | the first 8 |
| the indicators among the findings | the first 40 |
| each kind of target and of exposure | the first 40 |
| the lines of evidence of a finding or a target | the first 3 |
| the lines of evidence of an impact or an action | the first 6 |
| the targets of an impact or an action | the first 12 |
| what a mitigation is for | the first 6 activities |

## 2. Evidence text

Text taken from the evidence is attacker-controlled. In the report, a text prints unchanged only
when it is valid UTF-8, free of leading and trailing spaces, does not start with a double quote
and holds only printable characters. Any other text prints as a Go quoted string, so a control
sequence cannot reach the terminal and one entry line is always one line:

```text
  1  2026-10-22T09:00:00Z  script  "odd\x1b[31mname.sh"
```

A cell, a detail or a title is escaped whole. Error messages on standard error are escaped the
same way. JSON is encoded by `encoding/json`, and every rune that is not printable is then written
as a `\u` escape, so the value read back is the value in the evidence.

## 3. Secrets

A password, a hash, a token and a key are secrets. A secret is written as its first two
characters, at most eight stars, its last character and its length: `Wi********! (11 chars)`. A
secret of four characters or fewer is all stars.

- The mask stands wherever the secret would: in the exposure, inside a command quoted as evidence,
  in a target and as the value of an indicator. A secret shorter than six characters is masked in
  the exposure only, because it cannot be told from an ordinary word inside a line.
- The header of a private key block is written as the name of the key, such as
  `rsa private key`: it gives nothing away.
- `-secrets shown` writes every secret as it stands in the evidence, on the screen and in the
  saved files.

## 4. The saved files

Every run saves ten files to its output folder.

| File | Holds |
| --- | --- |
| `report.txt` | the report as plain text, as the screen shows it without colour |
| `report.md` | the report as Markdown |
| `report.html` | the report as one HTML page |
| `files.json` | the `file` class |
| `trace.json` | the `trace` class |
| `intents.json` | the `intent` class |
| `findings.json` | the `finding` class |
| `targeted.json` | the `targeted` class |
| `exposure.json` | the `exposure` class |
| `report.json` | the `report` class |

The three report files hold the same report: every section, whichever were named, with the same
entries, the same limits and the same masking, and without the line that names the output folder.

### Markdown

- The title is the first heading, a section is a second-level heading and a group a third.
- A group whose entries have no detail lines is a table with a header row. Any other group is a
  list, each entry one item with its detail lines as items under it.
- Every value and every line of evidence is a code span, so a viewer shows it as written and
  makes no link, no formatting and no HTML of it.

### HTML

- `report.html` is one file that needs no other: its style is inside it, and it follows the
  light or dark setting of the browser.
- It holds no script, no image, no form and no link out of the page. The links at the top lead
  to its sections.
- Its content security policy is `default-src 'none'; style-src 'unsafe-inline'`, so a browser
  loads nothing when it is opened.
- A group is a table with a header row, and the detail lines of an entry stand in a panel under
  its row. Every text of the evidence is escaped.

## 5. JSON

A JSON file is one array of objects, one object per row, with the keys of its class in the order
of the tables below.

```text
$ cat slopmop-ai_workdir/files.json
[
  {
    "name": "20250302_090000_step01_inventory.ps1",
    "role": "script",
    "size": 487,
    "lines": 13,
    "modified": "2025-03-02T09:00:03Z",
    "sha256": "2232e80ab6e9391a221315e0b9aaf9dd70739833a376a0e3ee4e671251be09d6",
    "name_time": "20250302_090000",
    "note": null
  }
]
```

- Times are ISO 8601 in UTC to seconds: `2026-10-04T09:14:02Z`.
- A size is a count of bytes and a hash is whole.
- A value that does not apply is `null`.
- A list is one string, joined with `, `. Two lists are joined otherwise, because their items
  hold commas: `targets` with `; ` and `evidence` with a line break.

## 6. Classes

The columns of each class are declared in `internal/command/commands.json`.

### file

One row per file, sorted by name in byte order.

| JSON key | Value |
| --- | --- |
| `name` | the path below the input folder |
| `role` | `script`, `output` or `other` |
| `size` | bytes read |
| `lines` | lines of text; `null` when the file has a note |
| `modified` | the modified time |
| `sha256` | SHA-256 of the raw bytes; `null` when the file is unreadable |
| `name_time` | the timestamp exactly as it stands in the file name; `null` when there is none |
| `note` | `binary`, `oversize`, `unreadable`, or `null` |

### trace

One row per file, in time order: the time in the file name, or else the modified time.

| JSON key | Value |
| --- | --- |
| `step` | the number of the script this file belongs to; `0` before the first script |
| `name` | the path below the input folder |
| `role` | `script`, `output` or `other` |
| `time` | the file-name timestamp read as UTC, or else the modified time, as one ISO-8601 instant to the second; the file name's own token stays in the `file` class `name_time` |
| `intent` | the ARTEX intent the file belongs to, such as `i1042`; `null` when its path names none |
| `tools` | the commands the file runs or records |
| `tactics` | the tactics of those tools and of the activities |
| `transforms` | encodings and ciphers applied |
| `activities` | the activities the file shows, in the order of `activities.json` |
| `outputs` | the files a script writes |
| `indicators` | the number of distinct indicators |
| `intel` | watchlist matches as `attribution: value`; `null` without `-intelfile` |
| `note` | `binary`, `oversize`, `unreadable`, or `null` |

### finding

One row per activity, per distinct indicator and per tactic.

| JSON key | Value |
| --- | --- |
| `finding` | the activity's name, the indicator's type, or `tactic` |
| `severity` | the highest severity among the tactics; `high` for a watchlist match |
| `tactic` | the tactics of the activity, or of the files that hold the indicator |
| `indicator` | the indicator's value; `null` on an activity or tactic row |
| `files` | the files that show it |
| `attribution` | the watchlist attributions of an indicator; `null` otherwise |
| `attack` | on an activity, its MITRE ATT&CK techniques; on a tactic, its ATT&CK tactic; `null` on an indicator |
| `atlas` | on an activity, its MITRE ATLAS techniques; on a tactic, its ATLAS tactic; `null` on an indicator |
| `evidence` | on an activity, the first 24 lines that show it, each with its place; `null` otherwise |

Sort: severity from `high` to `low`, then activities, indicators and tactics, each by name.

### targeted

One row per username, IP address, hostname or email address that a script names outright: a value
written in a script, or the plain value of a variable a script sets. A secret is never a row.

| JSON key | Value |
| --- | --- |
| `kind` | `username`, `email`, `device` for a hostname, or `ip` |
| `value` | the value as the script holds it |
| `origin` | `prior` when no earlier file of the timeline that is not a script holds the value: the scripts were written knowing it. `discovered` when one does: the run learnt it first |
| `from` | the place in the output that held a discovered value first; `null` on a prior one |
| `scope` | on an address, `private` for a private, loopback or link-local address and `public` for any other; a range is judged by its first address; `null` on the other kinds |
| `count` | the script lines that name the value |
| `scripts` | the first five places that name it |
| `evidence` | the script lines at those places, each with its place, with every secret masked |

Sort: usernames, email addresses, hostnames, then addresses; `prior` before `discovered`; then by
value. Two values that differ only in case are one row.

- The usernames, email addresses and addresses are found as for the `exposure` class. A hostname
  is a device of that class or a domain name: a domain a script names is a host it reaches for.
- A `prior` value is `medium` in the report and a `discovered` one is `low`.
- A value the scripts read from an output at run time is in no script, so it is not a row.

### exposure

One row per distinct value. A secret is one row per value and account.

| JSON key | Value |
| --- | --- |
| `kind` | `password`, `username`, `email`, `device` or `ip` |
| `value` | the value; a secret is masked unless `-secrets shown` |
| `account` | whose a secret is, when the evidence says; `null` otherwise |
| `form` | what a secret is: `password`, `hash`, `token`, `key` or `secret`; `null` on the other kinds |
| `seen` | `collected` when the value is first seen in an output, in the order of the timeline: the scripts gathered it. `used` when it is first seen in a script: the attacker brought it |
| `severity` | `high` for a secret, `medium` for a username and an email address, `low` for a device and an address |
| `count` | the lines that hold the value |
| `files` | the first five places that hold it |

Sort: the kinds in the order above, `collected` before `used`, then by value.

- A username is a value under a field that names an account, a login a tool reports, the account of
  a `passwd` line, a dumped hash, a home or profile folder, a remote login or a `DOMAIN\user`. A
  domain before the name is dropped.
- An email address and an IP address are the indicators of those types. A loopback address is
  left out.
- A device is a value under a field that names a host, the host of a share, a scan report or a
  remote login, a name a tool reports, and a name in `.local`, `.lan`, `.internal`, `.corp` or
  `.intranet`.
- A secret is a value under a field whose name ends as `password`, `secret`, `token` or `key`
  does, a password a tool reports or is given, the hash of a dumped account or of a `shadow` line,
  a password inside an address, a bearer token, and the indicators `JWT`, `AWSKey` and
  `PrivateKey`. The same NT hash is one value however it is written.
- A secret takes the account of its own record, line or tool option. Under a field name it takes
  the username read at most three lines before it, unless both field names begin differently:
  `DB_PASSWORD` is the password of `DB_USER` and `API_TOKEN` is not.
- A value that is a variable is given what the script sets it to; a placeholder is left out.

### report

One row per line of the report, in seven sections.

| Section | A row is |
| --- | --- |
| `summary` | a count: `files`, `scripts`, `outputs`, `left out` with `-start` or `-stop`, `indicators` and one per type, `activities` and one per activity, `tactics`, `targeted` and one per kind, `exposed` and one per kind, `intents` when a file belongs to one, and `intel hits` with `-intelfile` |
| `script`, `output`, `other` | a notable file, under its role: one that holds a finding of high severity |
| `targeted` | a value a script names outright, as the `targeted` class holds it: `item` is the value, `value` is `medium` for a prior one and `low` for a discovered one, `detail` the kind, the origin, the scope and the place that held it first, `files` the places in the scripts and `evidence` the lines |
| `exposure` | an exposed value, as the `exposure` class holds it: `item` is the value, `value` the severity, `detail` the kind, whose a secret is and whether it was collected or used, and `files` its places |
| `impact` | a consequence the evidence shows |
| `remediation` | an action that undoes what was done |
| `mitigation` | a mitigation that MITRE ATT&CK or MITRE ATLAS gives for a technique that was found |

| JSON key | Value |
| --- | --- |
| `item` | the name of the count, the path of the file, the impact or the action; on a mitigation, its identifier and name, such as `M1038 Execution Prevention` |
| `section` | the section; a notable file carries its role |
| `value` | a number on a summary row, where an `activities <name>` row counts the lines that show the activity; elsewhere `low`, `medium` or `high`: the severity of a file or an impact, the priority of an action; a mitigation takes the highest severity among the activities it addresses |
| `detail` | on a file, what was found: activities, tools with their tactic, watchlist attributions; on an impact, its statement and the hosts or addresses affected; on a remediation, what to do; on a mitigation, the first sentence of the framework's own description; on the summary row `left out`, what the window left out: `before 2026-10-22T09:10:00Z or after 2026-10-22T09:20:00Z`; `null` on any other summary row |
| `basis` | on an impact or an action, the activities, tool tactics and watchlist attributions that call for it |
| `files` | on a script, the files it writes; on another file, the scripts that write it; on an impact or an action, the files that show it |
| `attack` | the ATT&CK techniques a file or an impact shows; on an ATT&CK mitigation, the techniques found that it addresses |
| `atlas` | the ATLAS techniques a file or an impact shows; on an ATLAS mitigation, the techniques found that it addresses |
| `targets` | on an impact or an action, what it concerns: the subjects of its activities and the exposed values it lists; on a mitigation, each activity it answers with what that activity acted on |
| `evidence` | on an impact or an action, the lines that show it, each with its place: up to 24 of each activity and of the tools of each tactic |

Sort: the sections in the order above; files in time order; impacts from `high` to `low`;
remediation from `high` to `low`; then the ATT&CK mitigations and the ATLAS mitigations, each from
`high` to `low` and by identifier.

An impact says what the evidence shows was done. The tool does not run a script, so it cannot say
whether a step succeeded.

### intent

One row per ARTEX intent, in the order the intents began. ARTEX gives each intent a run folder,
`tasks/<task>/i<number>`, and names the session of its worker `exp<number>-worker-i<number>`. A
file belongs to the intent whose folder it lies in, at any depth, or whose session its path names.

| JSON key | Value |
| --- | --- |
| `intent` | the identifier, `i` and the number, such as `i1042` |
| `task` | the task of the run folder; `null` when the path does not give one |
| `first` | the time of its earliest file, as the `trace` class writes a time; `null` when no file has a time |
| `last` | the time of its latest file |
| `seconds` | the seconds from `first` to `last`; `0` for a single file |
| `severity` | the highest severity among the tactics of its files; `null` when they show none |
| `tactics` | the tactics of its files |
| `attack` | the ATT&CK techniques of the activities its files show |
| `atlas` | the ATLAS techniques of those activities |
| `activities` | the activities its files show |
| `files` | its files, in time order |

- The period is that of the files: the timestamp in a file name, or else the modified time. A
  copy that does not keep modified times moves the period of files that have no timestamp.
- A folder named `i386`, `i486`, `i586` or `i686` is no intent.
- When the folder read is a run folder itself, its files belong to that intent.
- A file outside every run folder belongs to no intent and is in no row.
