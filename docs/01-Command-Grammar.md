# Command grammar

`slopmop <folder> [section ...] [--intelfile <file>]`

`slopmop NOUN VERB [selectors] [--params] [output flags] [positional]`

The first form is the tool: one folder in, the whole analysis out. The second prints one view of
the same analysis as a table or as JSON. One sentence governs the second: **a noun names a kind of
thing, a verb acts on it, and every flag states by its prefix what kind of flag it is.**

## 1. The folder alone

`slopmop <folder>` reads every file in the folder and in its sub-folders, 16 levels down, analyses
them once and prints every section of the readout. Nothing in the folder is run and nothing is
written to it. No flag is needed.

| Section | Holds |
| --- | --- |
| `summary` | the counts |
| `timeline` | each file in order, with what it shows |
| `findings` | each activity, indicator and tactic, most severe first |
| `files` | the files that hold a finding of high severity |
| `impact` | what the findings mean |
| `remediation` | what to do about them, most urgent first |
| `mitigation` | what MITRE ATT&CK and ATLAS say prevents the techniques found |

- A section named after the folder prints only that section; several can be named, in any order
  and on either side of the folder. The sections always print in the order of the table.
- `--intelfile <file>` names a watchlist, and the readout attributes the indicators it matches.
- The first argument is a noun when it names one, so a folder called `file`, `report` or the like
  is written `./file`. Elsewhere a word that names a section is the section, so a folder called
  `impact` is written `./impact`.
- The form takes no output flags. The sections and the command's summary are declared in the
  `whole` block of `internal/command/nouns.json`.
- A sub-folder that is deeper than 16 levels or cannot be read is left out: the readout prints,
  then the command fails with exit code 1 and an error that names each such folder.

| Command | What it does |
| --- | --- |
| `slopmop case42/ai_workdir` | the whole analysis |
| `slopmop case42/ai_workdir impact remediation` | two sections |
| `slopmop case42/ai_workdir --intelfile watchlist.json` | the whole analysis, with the watchlist matches |

| Command | Error |
| --- | --- |
| `slopmop impact` | `the word "impact" names a section; give the folder too: slopmop <folder> impact` |
| `slopmop --intelfile watchlist.json` | `slopmop needs a folder: slopmop <folder>` |
| `slopmop case42 other` | `slopmop reads one folder, got "case42" and "other" (valid sections: summary, timeline, findings, files, impact, remediation, mitigation)` |
| `slopmop case42 -o json` | `-o applies only to verbs that print rows` |
| `slopmop case42/missing` | `not a folder: open case42/missing: no such file or directory` |

## 2. Nouns and verbs

| Noun | Alias | Verb | Alias | Meaning |
| --- | --- | --- | --- | --- |
| `file` | `files` | `list` | `ls` | lists the files in the input directory, one per row |

The nouns, their verbs, aliases, summaries and columns are declared in
`internal/command/nouns.json`. Help and registration are built from that file.

`list` is a global verb: it means the same on every noun, takes no positional, and treats an omitted
selector as every member. Its name and alias are defined once, in `cli.ListVerb`. A verb named
`list`, `get` or `delete` always carries the alias `ls`, `show` or `rm`, and those aliases belong
to no other verb.

## 3. The four flag kinds

| Kind | Form | Meaning | Takes a value |
| --- | --- | --- | --- |
| Selector | `-name` | one member of a closed set; combinable; none means all | no |
| Param | `--name value` or `--name=value` | a typed parameter | yes |
| Switch | `--name`, or its one-letter short form `-n` | turns a behaviour on | no |
| Output flag | `-o wide\|json`, `-q`, `--no-headers`, `--tz local\|utc` | how rows are printed | as shown |

The prefix is enforced: a wrong prefix is a specific error, not a guess. A param given twice is an
error. `--` ends the flags; everything after it is positional.

A switch is written where a param is. A verb's spec declares each switch and its short form; a short
form is one lower-case letter that no selector, switch or output flag of the verb uses.

Selectors are data-driven. The selectors of `file list` are the roles declared in
`internal/inventory/roles.json`: `-script`, `-output`, `-other`.

Output flags are the same on every verb that prints rows and are rejected on every other verb.
`-q` cannot be combined with `-o`.

## 4. The input directory

`--inputdir <folder>` names the directory of scripts and outputs to read. It is a required param of
every verb that reads evidence: there is no default and nothing is remembered between runs, so a
command line states its own input in full. A verb's spec lists its required params, and the parser
rejects a command line that leaves one out.

Without a switch, only the files directly in the directory are read. `--recursive`, or `-r`, reads
the sub-folders too, 16 levels down. Column 1 is then the path below the input directory, with `/`
between its elements. A sub-folder that is deeper than 16 levels or cannot be read is left out: the
rows print, then the command fails with exit code 1 and an error that names each such folder.

## 5. Works

| Command | What it does |
| --- | --- |
| `slopmop file list --inputdir case42/ai_workdir` | every file in the directory |
| `slopmop files ls --inputdir=case42/ai_workdir` | the same, through the aliases and the `=` form |
| `slopmop file list --inputdir case42/ai_workdir -script` | only scripts |
| `slopmop file list --inputdir case42/ai_workdir -script -other` | two roles at once |
| `slopmop file list --inputdir case42/ai_workdir -o wide` | every column |
| `slopmop file list --inputdir case42/ai_workdir -q -script` | script names only, one per line |
| `slopmop file list --inputdir case42/ai_workdir --recursive` | every file in the directory and its sub-folders |
| `slopmop trace list --inputdir case42/ai_workdir -r` | the timeline across the sub-folders |
| `slopmop finding list --inputdir case42/ai_workdir -activity -r` | the activities found, across the sub-folders |
| `slopmop report list --inputdir case42/ai_workdir --intelfile watchlist.json` | the whole report, with the watchlist matches |
| `slopmop report list --inputdir case42/ai_workdir -impact -remediation` | two sections of the report |
| `slopmop report list --inputdir case42/ai_workdir -files --severity medium` | the files with a finding of medium severity or above |

## 6. Fails

| Command | Error |
| --- | --- |
| `slopmop bogus list` | `slopmop reads one folder, got "bogus" and "list" (valid sections: summary, timeline, findings, files, impact, remediation, mitigation)` |
| `slopmop file bogus` | `file has no verb "bogus"` |
| `slopmop file list` | `file list needs --inputdir <folder>` |
| `slopmop file list -inputdir case42` | `-inputdir takes a value; use --inputdir <folder>` |
| `slopmop file list --inputdir` | `--inputdir needs a value <folder>` |
| `slopmop file list --inputdir a --inputdir b` | `--inputdir given more than once` |
| `slopmop file list --inputdir case42 -bogus` | `unknown selector -bogus (valid selectors: -other, -output, -script)` |
| `slopmop file list --inputdir case42 --role x` | `unknown option --role (valid params: --inputdir <folder>)` |
| `slopmop file list --inputdir case42 --script` | `--script takes no value; "script" is a selector, use -script` |
| `slopmop file list --inputdir case42 -recursive` | `-recursive is a switch; use --recursive` |
| `slopmop file list --inputdir case42 --r` | `--r is a short form; use -r or --recursive` |
| `slopmop file list --inputdir case42 --recursive=yes` | `--recursive takes no value` |
| `slopmop file list --inputdir case42 extra` | `file list expects no positional args, got 1` |
| `slopmop file list --inputdir case42 -o yaml` | `unknown view "yaml" (valid views: json, wide)` |
| `slopmop file list --inputdir case42 -q -o json` | `-q cannot be combined with -o` |
| `slopmop file list --inputdir case42/missing` | `not a folder: open case42/missing: no such file or directory` |

## 7. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success, including requested help |
| 1 | the command ran and failed |
| 2 | usage error: the command line does not fit the grammar |

Errors go to standard error as `error: <message>`. A message that carries a file name from the
evidence is escaped as described in the [output schema](02-Output-Schema.md).

## 8. Help

Help is generated from the registered nouns and each verb's spec, so it cannot drift from the
parser. `slopmop`, `slopmop help`, `slopmop -h` and `slopmop --help` print the usage of the folder
form, its sections and the nouns. `slopmop NOUN` lists its verbs. `-h` or `--help` after a verb prints that verb's selectors, params, switches and output flags.

```text
$ slopmop file list -h
usage: slopmop file list --inputdir <folder> [selectors] [--params] [output flags]
list the files in the input directory

selectors (single dash, pick any; none = all):
  -other          any other file
  -output         an output a script produced
  -script         a script the agent wrote

params (double dash, take a value):
  --inputdir      <folder> (required)

switches (double dash, take no value; the short form takes one dash):
  --recursive, -r read sub-folders too, 16 levels down

output flags:
  -o wide|json    every column, or JSON
  -q              column 1 only, one per line
  --no-headers    no header row
  --tz local|utc  zone of displayed times (default utc)
```
