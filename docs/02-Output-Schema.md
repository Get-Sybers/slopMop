# Output schema

The conventions every `list` output obeys, then the view of each class.

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

Sort: severity from `high` to `low`, then activities, indicators and tactics, each by name.

### report

One row per count: `files`, `scripts`, `outputs`, `indicators` and one row per indicator type,
`activities` and one row per activity, `tactics`, and `intel hits` when `--intelfile` is given.

| Column | JSON key | Value |
| --- | --- | --- |
| `METRIC` | `metric` | the name of the count |
| `VALUE` | `value` | distinct values; on an `activities <name>` row, the lines that show the activity |
