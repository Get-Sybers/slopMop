# Command grammar

`slopmop -inputdir <folder> VERB [section ...] [options]`

One sentence governs the rest: **an option names its value, a verb says what to do with the
folder, and the bare words after the verb choose what the verb prints.**

## 1. Verbs

| Verb | Meaning |
| --- | --- |
| `report` | reads the folder and everything below it, runs nothing, prints the report and saves it |

The verbs, their sections, their options and the files they save are declared in
`internal/command/commands.json`. Help and registration are built from that file. A verb that is
declared without an implementation, or implemented without a declaration, stops the program at
start.

## 2. Options

| Option | Value | Meaning |
| --- | --- | --- |
| `-inputdir` | `<folder>` | the folder of scripts and outputs to read; `report` requires it |
| `-intelfile` | `<file>` | a watchlist, JSON or STIX 2.1, to attribute the indicators to |
| `-outdir` | `<folder>` | where the output is saved |

- An option is written with one dash or two, and its value follows as the next argument or after
  `=`: `-inputdir case42`, `--inputdir case42`, `-inputdir=case42`.
- Every option takes a value, so the argument after an option is its value whatever it looks like.
- An option stands before the verb or after it. An option given twice is an error. `--` ends the
  options.
- There is no default input folder and nothing is remembered between runs, so a command line
  states its own input in full.

## 3. Sections

The bare words after `report` name sections of the report. No word means every section.

| Section | Holds |
| --- | --- |
| `summary` | the counts |
| `timeline` | each file in order, with what it shows |
| `findings` | each activity, indicator and tactic, most severe first |
| `files` | the files that hold a finding of high severity |
| `impact` | what the findings mean |
| `remediation` | what to do about them, most urgent first |
| `mitigation` | what MITRE ATT&CK and ATLAS say prevents the techniques found |

The sections print in the order of the table, whatever order they are named in.

## 4. What report does

- It reads every file in the input folder and in its sub-folders, 16 levels down, and analyses them
  once. Nothing in the folder is run and nothing is written to it.
- It prints the sections named, as the [output schema](02-Output-Schema.md) describes.
- It saves the report with every section, whichever were named, and each class of the output
  schema as JSON: `report.txt`, `files.json`, `trace.json`, `findings.json` and `report.json`. A
  file of an earlier run is replaced. The last lines of the output name the folder.
- The output folder is `slopmop-<name of the input folder>` in the current directory. When the
  current directory is the input folder or inside it, the output folder is made beside the input
  folder. `-outdir <folder>` names another, which is made when it is missing. An output folder
  inside the input folder is refused before anything is read, with symbolic links resolved.
- When the output cannot be written, the report still prints, and the command then fails with exit
  code 1.
- A sub-folder that is deeper than 16 levels or cannot be read is left out: the report prints and
  is saved, then the command fails with exit code 1 and an error that names each such folder.

## 5. Works

| Command | What it does |
| --- | --- |
| `slopmop -inputdir case42/ai_workdir report` | prints and saves the whole report |
| `slopmop -inputdir case42/ai_workdir report impact remediation` | prints two sections; saves the whole report |
| `slopmop -inputdir case42/ai_workdir report -intelfile watchlist.json` | the whole report, with the watchlist matches |
| `slopmop -inputdir case42/ai_workdir report -outdir reports/case42` | the whole report, saved to `reports/case42` |
| `slopmop --inputdir=case42/ai_workdir report` | the same as the first, in the other spelling |

## 6. Fails

| Command | Error |
| --- | --- |
| `slopmop -inputdir case42` | `slopmop needs a verb (verbs: report)` |
| `slopmop -inputdir case42 list` | `unknown verb "list" (verbs: report)` |
| `slopmop report` | `report needs -inputdir <folder>` |
| `slopmop report -inputdir` | `-inputdir needs a value <folder>` |
| `slopmop -inputdir a -inputdir b report` | `-inputdir given more than once` |
| `slopmop -inputdir case42 report bogus` | `report has no section "bogus" (sections: summary, timeline, findings, files, impact, remediation, mitigation)` |
| `slopmop -inputdir case42 report -o json` | `unknown option -o (options: -inputdir <folder>, -intelfile <file>, -outdir <folder>)` |
| `slopmop -inputdir case42/missing report` | `not a folder: open case42/missing: no such file or directory` |
| `slopmop -inputdir case42 report -outdir case42/out` | `-outdir is inside the folder that is read; the evidence is never written to` |

## 7. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success, including requested help |
| 1 | the command ran and failed |
| 2 | usage error: the command line does not fit the grammar |

Errors go to standard error as `error: <message>`. A message that carries a file name from the
evidence is escaped as described in the [output schema](02-Output-Schema.md).

## 8. Help

Help is generated from the registered verbs, so it cannot drift from the parser. `slopmop`,
`slopmop help`, `slopmop -h` and `slopmop --help` list the verbs and the options, with or without
an option beside them: `slopmop -inputdir <folder> --help`. With a verb, the same words print the
help of the verb. The value of an option is never read as a request for help.

```text
$ slopmop report --help
usage: slopmop -inputdir <folder> report [section ...] [-intelfile <file>] [-outdir <folder>]
reads the folder and everything below it, runs nothing, prints the report and saves it

sections (name any to print only those; none = all):
  summary             the counts
  timeline            each file in order, with what it shows
  findings            each activity, indicator and tactic, most severe first
  files               the files that hold a finding of high severity
  impact              what the findings mean
  remediation         what to do about them, most urgent first
  mitigation          what MITRE ATT&CK and ATLAS say prevents the techniques found

options (one dash or two; each takes a value):
  -inputdir <folder>  the folder of scripts and outputs to read (required)
  -intelfile <file>   a watchlist, JSON or STIX 2.1, to attribute the indicators to
  -outdir <folder>    where the output is saved; slopmop-<name> in the current directory when not given
```
