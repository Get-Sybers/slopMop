# Output schema

The conventions every `list` output obeys, the view of each class, and then the readout that
`slopmop <folder>` prints.

## 1. Views

- **default**: the columns read first, lean enough for a normal terminal width.
- **`-o wide`**: every column the class carries, with raw values.
- **`-o json`**: one array of objects, every column, raw values, for programs.

## 2. Columns

- Column 1 is the selector: the exact string to hand back to the tool.
- Headers are UPPERCASE, space padded, with no borders. `--no-headers` drops the header row.
- Columns are separated by two or more spaces.

## 3. Time

- Times are ISO 8601 in UTC to seconds: `2026-10-04T09:14:02Z`.
- `--tz local` shows them in the host time zone with its offset: `2026-10-04T19:14:02+10:00`.
- JSON times are always UTC.

## 4. Counts

- A total count keeps a plain noun or `count`.
- A distinct count takes the lowercase prefix `n-<field>`. The lowercase header breaks the
  UPPERCASE rule on purpose, so a distinct count never reads as a field.

## 5. Values

- Sizes are humanised to binary units in the default view (`487 B`, `1.2 KiB`, `54 MiB`) and are
  raw byte counts in wide and JSON.
- Hashes are cut to 12 characters in the default view and are full in wide and JSON.
- Sentinels: `-` means not applicable, `never` means an event that has not happened. Both are
  `null` in JSON.

## 6. Evidence text

Text taken from the evidence is attacker-controlled. In the default view, in wide and under `-q`, a
value prints unchanged only when it is non-empty, valid UTF-8, free of leading and trailing
spaces, does not start with a double quote and holds only printable characters. Any other value
prints as a Go quoted string, so a control sequence cannot reach the terminal and one row is always
one line:

```text
$ slopmop file list --inputdir case42 -q
"odd\x1b[31mname.txt"
```

Error messages on standard error are escaped the same way. JSON is encoded by `encoding/json`, and
every rune that is not printable is then written as a `\u` escape, so the value read back is the
value in the evidence.

## 7. Scripting

`-q` prints column 1 only, one per line. `--no-headers` strips the header row. `-o json` gives full
fidelity. Truncating and humanising apply to the default view only.

```text
$ slopmop file list --inputdir case42/ai_workdir -other -o json
[
  {
    "name": "ca01_20250302_092210.cer",
    "role": "other",
    "size": 18,
    "lines": null,
    "modified": "2025-03-02T09:22:13Z",
    "sha256": "611ae0e982ec96df79fcb8dcc302cee5e41392be134ea0b6a6cfb7126f6c5951",
    "name_time": "20250302_092210",
    "note": "binary"
  }
]
```

## 8. Classes

### file

```text
$ slopmop file list --inputdir case42/ai_workdir -script
NAME                                   ROLE    SIZE   LINES  MODIFIED
20250302_090000_step01_inventory.ps1   script  487 B  13     2025-03-02T09:00:03Z
20250302_090500_step02_sync.ps1        script  385 B  7      2025-03-02T09:05:03Z
20250302_090900_step03_sync_retry.ps1  script  478 B  13     2025-03-02T09:09:03Z
20250302_091500_step04_certs.ps1       script  387 B  7      2025-03-02T09:15:03Z
20250302_092200_step05_export.ps1      script  639 B  12     2025-03-02T09:22:03Z
```

| Column | JSON key | Value |
| --- | --- | --- |
| `NAME` | `name` | the path below the input directory |
| `ROLE` | `role` | `script`, `output` or `other` |
| `SIZE` | `size` | bytes read |
| `LINES` | `lines` | lines of text; `-` when the file has a note |
| `MODIFIED` | `modified` | the modified time |
| `SHA256` (wide) | `sha256` | SHA-256 of the raw bytes; `-` when the file is unreadable |
| `NAME TIME` (wide) | `name_time` | the timestamp exactly as it stands in the file name; `-` when there is none |
| `NOTE` (wide) | `note` | `binary`, `oversize`, `unreadable`, or `-` |

Sort: name, in byte order. `NAME TIME` is text from the name: `--tz` does not shift it.

### trace

One row per file, in time order: the time in the file name, or else the modified time.

| Column | JSON key | Value |
| --- | --- | --- |
| `STEP` | `step` | the number of the script this file belongs to; `0` before the first script |
| `NAME` | `name` | the path below the input directory |
| `ROLE` | `role` | `script`, `output` or `other` |
| `TIME` | `time` | the timestamp in the file name as it stands, or else the modified time |
| `TOOLS` | `tools` | the commands the file runs or records |
| `TACTICS` | `tactics` | the tactics of those tools and of the activities |
| `TRANSFORMS` | `transforms` | encodings and ciphers applied |
| `ACTIVITIES` (wide) | `activities` | the activities the file shows, in the order of `activities.json` |
| `OUTPUTS` (wide) | `outputs` | the files a script writes |
| `INDICATORS` (wide) | `indicators` | the number of distinct indicators |
| `INTEL` (wide) | `intel` | watchlist matches as `attribution: value`; `-` without `--intelfile` |
| `NOTE` (wide) | `note` | `binary`, `oversize`, `unreadable`, or `-` |

A list is one cell joined with `, `. The default view cuts a list to 60 bytes.

### finding

One row per activity, per distinct indicator and per tactic. The selectors `-activity`,
`-indicator` and `-tactic` choose among them.

| Column | JSON key | Value |
| --- | --- | --- |
| `FINDING` | `finding` | the activity's name, the indicator's type, or `tactic` |
| `SEVERITY` | `severity` | the highest severity among the tactics; `high` for a watchlist match |
| `TACTIC` | `tactic` | the tactics of the activity, or of the files that hold the indicator |
| `INDICATOR` | `indicator` | the indicator's value; `-` on an activity or tactic row |
| `FILES` | `files` | the files that show it |
| `ATTRIBUTION` | `attribution` | the watchlist attributions of an indicator; `-` otherwise |
| `ATTACK` (wide) | `attack` | on an activity, its MITRE ATT&CK techniques; on a tactic, its ATT&CK tactic; `-` on an indicator |
| `ATLAS` (wide) | `atlas` | on an activity, its MITRE ATLAS techniques; on a tactic, its ATLAS tactic; `-` on an indicator |

Sort: severity from `high` to `low`, then activities, indicators and tactics, each by name.

### report

One row per line of the report, in five sections. A selector picks a section; none picks all.

| Section | Selector | A row is |
| --- | --- | --- |
| `summary` | `-summary` | a count: `files`, `scripts`, `outputs`, `indicators` and one per type, `activities` and one per activity, `tactics`, and `intel hits` with `--intelfile` |
| `script`, `output`, `other` | `-files` | a notable file, under its role: one that holds a finding at or above `--severity`, which is `high` unless given |
| `impact` | `-impact` | a consequence the evidence shows |
| `remediation` | `-remediation` | an action that undoes what was done |
| `mitigation` | `-mitigation` | a mitigation that MITRE ATT&CK or MITRE ATLAS gives for a technique that was found |

| Column | JSON key | Value |
| --- | --- | --- |
| `ITEM` | `item` | the name of the count, the path of the file, the impact or the action; on a mitigation, its identifier and name, such as `M1038 Execution Prevention` |
| `SECTION` | `section` | the section; a notable file carries its role |
| `VALUE` | `value` | a number on a summary row, where an `activities <name>` row counts the lines that show the activity; elsewhere `low`, `medium` or `high`: the severity of a file or an impact, the priority of an action; a mitigation takes the highest severity among the activities it addresses |
| `DETAIL` | `detail` | on a file, what was found: activities, tools with their tactic, watchlist attributions; on an impact, its statement and the hosts or addresses affected; on a remediation, what to do; on a mitigation, the first sentence of the framework's own description; `-` on a summary row |
| `BASIS` (wide) | `basis` | on an impact or an action, the activities, tool tactics and watchlist attributions that call for it |
| `FILES` (wide) | `files` | on a script, the files it writes; on another file, the scripts that write it; on an impact or an action, the files that show it |
| `ATTACK` (wide) | `attack` | the ATT&CK techniques a file or an impact shows; on an ATT&CK mitigation, the techniques found that it addresses |
| `ATLAS` (wide) | `atlas` | the ATLAS techniques a file or an impact shows; on an ATLAS mitigation, the techniques found that it addresses |

Sort: the sections in the order above; files in time order; impacts from `high` to `low`;
remediation from `high` to `low`; then the ATT&CK mitigations and the ATLAS mitigations, each from
`high` to `low` and by identifier.

An impact says what the evidence shows was done. The tool does not run a script, so it cannot say
whether a step succeeded.

## 9. The readout

`slopmop <folder>` prints plain lines for reading, not a table, and saves them with the classes
above to its output folder.

| File | Holds |
| --- | --- |
| `readout.txt` | the readout with every section, without colour and without the line that names the folder |
| `files.json` | the `file` class of the folder and its sub-folders, as `file list -r -o json` prints it |
| `trace.json` | the `trace` class, as `trace list -r -o json` prints it |
| `findings.json` | the `finding` class, as `finding list -r -o json` prints it |
| `report.json` | the `report` class, as `report list -r -o json` prints it |

With `--intelfile`, the JSON files carry the watchlist matches as the same command with that
param prints them.

```text
slopmop   case42/ai_workdir
[x] HIGH - 4 impacts: 2 high, 1 medium, 1 low
[x] high   [!] medium   [i] low

Summary
  files       16  6 scripts, 9 outputs
  indicators  13  1 Base64Blob, 4 Domain, 1 EncodedCommand, 1 GUID, 3 IPv4, 3 SHA1
  activities  1
  tactics     4

Impact
  [x] Credentials exposed
      Secrets, keys, certificates or stored passwords were read. Treat them as known to the attacker.
      basis  CertificateExport, CredentialAccess tools
      files  20250302_090900_step03_sync_retry.ps1, 20250302_092200_step05_export.ps1

[x] HIGH - 4 impacts: 2 high, 1 medium, 1 low
-> saved to slopmop-ai_workdir: readout.txt, files.json, trace.json, findings.json, report.json
-> one section: slopmop <folder> impact
-> a table or JSON: slopmop NOUN VERB -h
```

- Line 1 names the folder. Line 2 is the verdict: the highest severity among the impacts and the
  count at each, or `[ok] NOTHING FOUND in <n> files`. The verdict is repeated at the end when
  more than one section prints, where a terminal leaves the reader.
- A mark gives a severity or a priority: `[x]` high, `[!]` medium, `[i]` low. The marks are ASCII.
- A section is its title, then its entries indented two spaces. An entry is one line of cells,
  aligned with the entries around it, and detail lines indented under it, each with a label. A
  column is padded to at most 60 characters; a longer cell runs past it. A section with no entry
  prints `none`.
- A list of files gives the first three and counts the rest: `a.sh, b.sh, c.sh and 4 more`.
- The values are those of the classes: a timeline entry is a `trace` row, a finding entry is a
  `finding` row and the other sections are `report` rows. An activity's `lines` is its count in the
  summary of `report`. Times are UTC.
- Colour is used only when standard output is a terminal, `NO_COLOR` is unset and `TERM` is not
  `dumb`; on Windows, only inside Windows Terminal. A file or a pipe receives no colour code.
- Every text is escaped as section 6 describes, whole: a cell, a detail or a title that holds a
  character that is not printable prints as one quoted string.

| Section | Entry | Detail lines |
| --- | --- | --- |
| Summary | a count and its breakdown | none |
| Timeline | step, time, role, file | `tools`, `tactics`, `activities`, `transforms`, `wrote`, `watchlist`, `note`, `indicators` |
| Findings, activities | activity, lines, tactics, techniques | `in`: the files |
| Findings, indicators | type, value, files | `watchlist`: the attributions |
| Findings, tactics | tactic, its ATT&CK and ATLAS identifiers, files | none |
| Notable files | role, file | `found`, `linked` |
| Impact | the impact | its statement, `basis`, `files` |
| Remediation | the action | its text, `basis`, `files` |
| Mitigation | the mitigation, the techniques found that it addresses | none |
