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
| `-secrets` | `masked` or `shown` | how a password, a hash, a token or a key is written; `masked` when not given |
| `-cores` | a percentage, 1 to 100 | how much of the processors of this machine the run may use; all of them when not given |
| `-memory` | a percentage, 1 to 100 | how much of the memory of this machine the run tries to stay within; 75 when not given |
| `-progress` | `shown` or `hidden` | whether the run says what it is doing as it goes; `shown` on a terminal when not given |
| `-start` | a day, or a day and a time | reads only the files of this time or later; alone, it looks forward from this time |
| `-stop` | a day, or a day and a time | reads only the files of this time or earlier, a day alone counted to its end; alone, it looks back from this time |

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
| `timeline` | what was done, in order of time: each period of files that show the same tactics |
| `intents` | each ARTEX intent, by its run folder i\<number\>: its period and its ATT&CK and ATLAS techniques |
| `findings` | each activity, indicator and tactic, most severe first |
| `files` | the files that hold a finding of high severity |
| `targeted` | the usernames, addresses, hostnames and emails the scripts name outright |
| `exposure` | the usernames, emails, passwords, devices and addresses the files hold |
| `impact` | what the findings mean, with what each concerns and the lines that show it |
| `remediation` | what to do about them and to what, most urgent first |
| `mitigation` | what MITRE ATT&CK and ATLAS say prevents the techniques found |

The sections print in the order of the table, whatever order they are named in.

## 4. What report does

- It reads every file in the input folder and in its sub-folders, 16 levels down, and analyses them
  once. Nothing in the folder is run and nothing is written to it.
- It prints the sections named, as the [output schema](02-Output-Schema.md) describes.
- It saves the report with every section, whichever were named, as plain text, Markdown and
  HTML: `report.txt`, `report.md` and `report.html`.
- It saves each class of the output schema: `files.csv` and `exposure.csv` as CSV, and
  `trace.json`, `intents.json`, `findings.json`, `targeted.json` and `report.json` as JSON.
- A file of an earlier run is replaced. The last lines of the output name the folder.
- Nothing is written outside the output folder, apart from the folders above it that are
  missing and are made. Each saved file is made new in the folder: a link that stands under one
  of the names is replaced by the file, and what it led to, in the evidence or anywhere else, is
  left as it was.
- A secret is masked in everything it prints and saves: in the exposure, in a command quoted as
  evidence and among the indicators. `-secrets shown` writes each as it stands in the evidence.
- `-cores` and `-memory` take a percentage of the machine the run is on, with or without the
  sign: `-cores 50` is half of its processors, and never fewer than one. Neither changes anything
  the run writes.
- The memory limit is one the run works to keep: it frees what it no longer needs sooner as it
  nears the limit. What a folder needs in order to be analysed, the run still takes.
- `-start` and `-stop` set a window of time. Given together they bound it on both sides. `-start`
  alone looks forward: every file of that time or later is read. `-stop` alone looks back: every
  file of that time or earlier is read.
- A file whose time is outside the window is not opened: it is not hashed, not analysed and in
  no saved file. The time of a file is the one the timeline places it at: the time in its name,
  or else when it was last modified. A time written inside a file plays no part.
- A time is a day, `2026-10-22`, or a day and a time, `2026-10-22T09:30` or
  `2026-10-22T09:30:00Z`. It is UTC unless it names a zone, `2026-10-22T11:30:00+02:00`. A day
  alone is the whole day: `-start` begins at its first instant and `-stop` ends at its last, so
  `-start 2026-10-22 -stop 2026-10-22` is that one day. Both ends are counted in.
- A file whose name gives a day and no time is in the window when any part of that day is. A
  file with no time at all is outside every window.
- The summary of a run with a window has the row `left out`: how many files were outside it, and
  what the window left out. A report made with a window always says so.
- A run says what it is doing on standard error, never on standard output: the stage it is in
  of five, how many of the files or of the saved files are done, how long the stage has lasted
  and, once one has taken two seconds, the file it has been at for longest:
  `[2/5] analysing the files  137 of 200  12s  on audit_20261022.jsonl 9s`.
- On a terminal that is one line, written over as the run goes on and taken off before the
  report is printed. Where standard error is not a terminal nothing is said, unless
  `-progress shown` asks for it: a line is then written when a stage begins and every ten
  seconds while it lasts. `-progress hidden` says nothing on a terminal either.
- The output folder is `slopmop-<name of the input folder>` in the current directory. When the
  current directory is the input folder or inside it, the output folder is made beside the input
  folder. `-outdir <folder>` names another, which is made when it is missing. A drive that is
  read whole gives its letter for the name: `slopmop-E`.
- An output folder inside the input folder is refused before anything is read. A folder is
  inside by where it is: symbolic links are resolved, a second name for the input folder counts
  as the input folder, and a folder on another drive is never inside.
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
| `slopmop -inputdir case42/ai_workdir report exposure -secrets shown` | the exposure, with each secret written out |
| `slopmop -inputdir case42/ai_workdir report -progress shown 2> run.log` | the whole report, with a line for each stage in `run.log` |
| `slopmop -inputdir case42/ai_workdir report -start 2026-10-22 -stop 2026-10-23` | the report of the files of those two days |
| `slopmop -inputdir case42/ai_workdir report -start 2026-10-22T09:30` | looks forward: the report of the files from half past nine UTC on |
| `slopmop -inputdir case42/ai_workdir report -stop 2026-10-22T09:30` | looks back: the report of the files up to half past nine UTC |
| `slopmop --inputdir=case42/ai_workdir report` | the same as the first, in the other spelling |

## 6. Fails

| Command | Error |
| --- | --- |
| `slopmop -inputdir case42` | `slopmop needs a verb (verbs: report)` |
| `slopmop -inputdir case42 list` | `unknown verb "list" (verbs: report)` |
| `slopmop report` | `report needs -inputdir <folder>` |
| `slopmop report -inputdir` | `-inputdir needs a value <folder>` |
| `slopmop -inputdir a -inputdir b report` | `-inputdir given more than once` |
| `slopmop -inputdir case42 report bogus` | `report has no section "bogus" (sections: summary, timeline, intents, findings, files, targeted, exposure, impact, remediation, mitigation)` |
| `slopmop -inputdir case42 report -o json` | `unknown option -o (options: -inputdir <folder>, -intelfile <file>, -outdir <folder>, -secrets masked\|shown, -cores <percent>, -memory <percent>, -progress shown\|hidden, -start <time>, -stop <time>)` |
| `slopmop -inputdir case42 report -secrets plain` | `-secrets takes masked or shown, not "plain"` |
| `slopmop -inputdir case42 report -cores 0` | `-cores takes a percentage from 1 to 100, not "0"` |
| `slopmop -inputdir case42 report -progress loud` | `-progress takes shown or hidden, not "loud"` |
| `slopmop -inputdir case42 report -start yesterday` | `-start takes a day or a day and a time, such as 2026-10-22 or 2026-10-22T09:30:00Z, not "yesterday"` |
| `slopmop -inputdir case42 report -start 2026-10-23 -stop 2026-10-22` | `-stop 2026-10-22 is before -start 2026-10-23` |
| `slopmop -inputdir case42/missing report` | `not a folder: open case42/missing: no such file or directory` |
| `slopmop -inputdir case42 report -outdir case42/out` | `-outdir is inside the folder that is read; the evidence is never written to` |

## 7. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success, including requested help |
| 1 | the command ran and failed |
| 2 | usage error: the command line does not fit the grammar |

Errors go to standard error as `error: <message>`. A message that carries a file name from the
evidence is escaped as described in the [output schema](02-Output-Schema.md), and so is a file
name in the line that says what the run is doing.

## 8. Help

Help is written for the point the command line has come to. `-h`, `-help`, `--help` or the word
`help`, put anywhere on a line, prints what the line holds so far and what can follow it, and runs
nothing. It is generated from the registered verbs, so it cannot drift from the parser.

| Line so far | Help says |
| --- | --- |
| `slopmop --help`, or `slopmop` alone | the verbs and the options |
| `slopmop -inputdir --help` | the value the option takes |
| `slopmop -inputdir <folder> --help` | what was given, and the verbs to add |
| `slopmop -inputdir <folder> report --help` | what was given, the sections, and the options left to add |
| `slopmop -inputdir <folder> report impact --help` | the sections chosen and those left to add |
| `slopmop report --help` | the same as with a folder, and that `-inputdir` is still needed |

- `so far:` repeats the line. A value that holds a space or a character that is not printable is
  shown quoted.
- `given:` lists the options that have a value. `still needed:` lists the required options that
  are missing. The other blocks list what can be added: verbs, sections and options.
- `problems:` names what does not fit: an unknown verb, section or option, or an option given
  twice. Help is not an error, so the exit code is 0.
- `next:` is a line to type to see the help of the next point. `run:` is the command itself; it
  is shown once nothing is missing and nothing is wrong. Both leave out what was wrong, and write
  the line in the order of the usage line.
- A help flag where the value of an option belongs asks about that option. The word `help` there
  is the value, and so is anything after `=`: `-inputdir help`, `-inputdir=--help`.

```text
$ slopmop -inputdir case42 --help
usage: slopmop -inputdir <folder> VERB [section ...] [options]
so far: slopmop -inputdir case42

given:
  -inputdir case42        the folder of scripts and outputs to read

add a verb:
  report                  reads the folder and everything below it, runs nothing, prints the report and saves it

options you can add (one dash or two; each takes a value):
  -intelfile <file>       a watchlist, JSON or STIX 2.1, to attribute the indicators to
  -outdir <folder>        where the output is saved; slopmop-<name> in the current directory when not given
  -secrets masked|shown   how a password, a hash, a token or a key is written; masked when not given
  -cores <percent>        how much of the processors of this machine the run may use, 1 to 100; all of them when not given
  -memory <percent>       how much of the memory of this machine the run tries to stay within, 1 to 100; 75 when not given
  -progress shown|hidden  whether the run says what it is doing as it goes, on the error stream; shown on a terminal when not given
  -start <time>           reads only the files of this time or later, such as 2026-10-22 or 2026-10-22T09:30:00Z; alone, it looks forward from this time
  -stop <time>            reads only the files of this time or earlier, a day alone counted to its end; alone, it looks back from this time

next: slopmop -inputdir case42 report --help
```

```text
$ slopmop -inputdir case42 report impact --help
usage: slopmop -inputdir <folder> report [section ...] [-intelfile <file>] [-outdir <folder>] [-secrets masked|shown] [-cores <percent>] [-memory <percent>] [-progress shown|hidden] [-start <time>] [-stop <time>]
reads the folder and everything below it, runs nothing, prints the report and saves it
so far: slopmop -inputdir case42 report impact

given:
  -inputdir case42        the folder of scripts and outputs to read

sections chosen:
  impact                  what the findings mean, with what each concerns and the lines that show it

sections you can add:
  summary                 the counts
  timeline                what was done, in order of time: each period of files that show the same tactics
  intents                 each ARTEX intent, by its run folder i<number>: its period and its ATT&CK and ATLAS techniques
  findings                each activity, indicator and tactic, most severe first
  files                   the files that hold a finding of high severity
  targeted                what the scripts name and what activities acted on
  exposure                the usernames, emails, passwords, devices and addresses the files hold
  remediation             what to do about them and to what, most urgent first
  mitigation              what MITRE ATT&CK and ATLAS say prevents the techniques found

options you can add (one dash or two; each takes a value):
  -intelfile <file>       a watchlist, JSON or STIX 2.1, to attribute the indicators to
  -outdir <folder>        where the output is saved; slopmop-<name> in the current directory when not given
  -secrets masked|shown   how a password, a hash, a token or a key is written; masked when not given
  -cores <percent>        how much of the processors of this machine the run may use, 1 to 100; all of them when not given
  -memory <percent>       how much of the memory of this machine the run tries to stay within, 1 to 100; 75 when not given
  -progress shown|hidden  whether the run says what it is doing as it goes, on the error stream; shown on a terminal when not given
  -start <time>           reads only the files of this time or later, such as 2026-10-22 or 2026-10-22T09:30:00Z; alone, it looks forward from this time
  -stop <time>            reads only the files of this time or earlier, a day alone counted to its end; alone, it looks back from this time

next: slopmop -inputdir case42 report impact summary --help
run:  slopmop -inputdir case42 report impact
```
