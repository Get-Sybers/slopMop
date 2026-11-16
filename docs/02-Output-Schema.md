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
-> saved to slopmop-ai_workdir: report.txt, files.json, trace.json, findings.json, exposure.json, report.json
-> one section: slopmop -inputdir <folder> report impact
```

- Line 1 names the verb and the folder. Line 2 is the verdict: the highest severity among the
  impacts and the count at each, or `[ok] NOTHING FOUND in <n> files`. The verdict is repeated at
  the end when more than one section prints, where a terminal leaves the reader.
- A mark gives a severity or a priority: `[x]` high, `[!]` medium, `[i]` low. The marks are ASCII.
- A section is its title, then its entries indented two spaces. An entry is one line of cells,
  aligned with the entries around it, and detail lines indented under it, each with a label. A
  column is padded to at most 60 characters; a longer cell runs past it. A section with no entry
  prints `none`.
- A list of files gives the first three and counts the rest: `a.sh, b.sh, c.sh and 4 more`.
- A place in the evidence is written `file:line`, the line counted from 1 in the file as it
  stands. The line is left out where there is none: in a JSON, XML or HTML output, which is read by
  its values, and in a payload that was decoded out of a file.
- Detail lines that share a label stand under it, and the label is written once.
- A long list is cut and says how much more the saved files hold: the indicators and each kind of
  exposure after 40 entries, the lines of evidence of an impact or an action after 6, those of a
  finding after 3, and the targets after 12.
- Times are UTC.
- Colour is used only when standard output is a terminal, `NO_COLOR` is unset and `TERM` is not
  `dumb`; on Windows, only inside Windows Terminal. A file or a pipe receives no colour code.

| Section | Entry | Detail lines |
| --- | --- | --- |
| Summary | a count and its breakdown | none |
| Timeline | step, time, role, file | `tools`, `tactics`, `activities`, `transforms`, `wrote`, `watchlist`, `note`, `indicators` |
| Findings, activities | activity, lines, tactics, techniques | `what`: the lines that show it, each with its place |
| Findings, indicators | type, value, files | `watchlist`: the attributions |
| Findings, tactics | tactic, its ATT&CK and ATLAS identifiers, files | none |
| Notable files | role, file | `found`, `linked` |
| Exposure, a group per kind | the value, whether it was collected or used, the places; a secret also says what it is and whose | none |
| Impact | the impact | its statement; `targets`: what it concerns; `what`: the lines that show it; `basis`; `files` when no line is quoted |
| Remediation | the action | its text; `targets`: what to act on; `what`; `basis`; `files` when no line is quoted |
| Mitigation | the mitigation, the techniques found that it addresses | the framework's own sentence; `for`: each activity it answers and what that activity acted on |

The values are those of the classes of section 6: a timeline entry is a `trace` row, a finding
entry is a `finding` row, an exposure entry is an `exposure` row and the other sections are
`report` rows. An activity's `lines` is its count in the summary of the `report` class.

- A target is what a line acts on, with its kind: `account svc`, `unit sync.service`,
  `file /etc/sudoers.d/svc`, `url http://203.0.113.40/s.sh`. A variable the script sets is given
  its value and keeps its name: `file /tmp/tool ($F)`. A variable the script never sets is no
  target. An impact and an action also list the exposed values they concern:
  `password of app_rw`, `username deploy`.
- A line of evidence is the command as the file holds it, cut to 200 bytes, with its place. Under
  an impact or an action it begins with the activity or the tool it is evidence of:
  `AccountCreation: useradd -m -s /bin/bash svc (20261022_091500_step04_persist.sh:7)`.

## 2. Evidence text

Text taken from the evidence is attacker-controlled. In the report, a text prints unchanged only
when it is valid UTF-8, free of leading and trailing spaces, does not start with a double quote
and holds only printable characters. Any other text prints as a Go quoted string, so a control
sequence cannot reach the terminal and one entry line is always one line:

```text
  1  20261022_090000  script  "odd\x1b[31mname.sh"
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

Every run saves six files to its output folder.

| File | Holds |
| --- | --- |
| `report.txt` | the report with every section, whichever were named, without colour and without the line that names the output folder |
| `files.json` | the `file` class |
| `trace.json` | the `trace` class |
| `findings.json` | the `finding` class |
| `exposure.json` | the `exposure` class |
| `report.json` | the `report` class |

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
| `time` | the timestamp in the file name as it stands, or else the modified time |
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

One row per line of the report, in six sections.

| Section | A row is |
| --- | --- |
| `summary` | a count: `files`, `scripts`, `outputs`, `indicators` and one per type, `activities` and one per activity, `tactics`, `exposed` and one per kind, and `intel hits` with `-intelfile` |
| `script`, `output`, `other` | a notable file, under its role: one that holds a finding of high severity |
| `exposure` | an exposed value, as the `exposure` class holds it: `item` is the value, `value` the severity, `detail` the kind, whose a secret is and whether it was collected or used, and `files` its places |
| `impact` | a consequence the evidence shows |
| `remediation` | an action that undoes what was done |
| `mitigation` | a mitigation that MITRE ATT&CK or MITRE ATLAS gives for a technique that was found |

| JSON key | Value |
| --- | --- |
| `item` | the name of the count, the path of the file, the impact or the action; on a mitigation, its identifier and name, such as `M1038 Execution Prevention` |
| `section` | the section; a notable file carries its role |
| `value` | a number on a summary row, where an `activities <name>` row counts the lines that show the activity; elsewhere `low`, `medium` or `high`: the severity of a file or an impact, the priority of an action; a mitigation takes the highest severity among the activities it addresses |
| `detail` | on a file, what was found: activities, tools with their tactic, watchlist attributions; on an impact, its statement and the hosts or addresses affected; on a remediation, what to do; on a mitigation, the first sentence of the framework's own description; `null` on a summary row |
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
