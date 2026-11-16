# Command grammar

`slopmop NOUN VERB [selectors] [--params] [output flags] [positional]`

One sentence governs the rest: **a noun names a kind of thing, a verb acts on it, and every flag
states by its prefix what kind of flag it is.**

## 1. Nouns and verbs

| Noun | Alias | Verb | Alias | Meaning |
| --- | --- | --- | --- | --- |
| `evidence` | `ev` | `select [folder]` | | with a folder, selects it; without, prints the selected folder |
| `file` | `files` | `list` | `ls` | lists the files directly in the evidence folder, one per row |

The nouns, their verbs, aliases, summaries and columns are declared in
`internal/command/nouns.json`. Help and registration are built from that file.

`list` is a global verb: it means the same on every noun, takes no positional, and treats an omitted
selector as every member. Its name and alias are defined once, in `cli.ListVerb`. The names `list`,
`get` and `delete` are accepted only with the aliases `ls`, `show` and `rm`.

## 2. The three flag kinds

| Kind | Form | Meaning | Takes a value |
| --- | --- | --- | --- |
| Selector | `-name` | one member of a closed set; combinable; none means all | no |
| Param | `--name value` or `--name=value` | a typed parameter | yes |
| Output flag | `-o wide\|json`, `-q`, `--no-headers`, `--tz local\|utc` | how rows are printed | as shown |

The prefix is enforced: a wrong prefix is a specific error, not a guess. A param given twice is an
error. `--` ends the flags; everything after it is positional.

Selectors are data-driven. The selectors of `file list` are the roles declared in
`internal/inventory/roles.json`: `-script`, `-output`, `-other`.

Output flags are the same on every verb that prints rows and are rejected on every other verb.
`-q` cannot be combined with `-o`.

## 3. The evidence folder

A verb that reads evidence takes the folder from `--evidence <folder>` when it is given, otherwise
from the folder `evidence select` stored. There is no implicit default: without either, the verb
fails. A given `--evidence` never falls back to the selection, and the selection is not read.

`evidence select <folder>` stores the absolute path in the state file, `slopmop/state.json` under the
user's configuration directory. It refuses a state file that lies inside the selected folder.

## 4. Works

| Command | What it does |
| --- | --- |
| `slopmop evidence select case42/ai_workdir` | selects the folder |
| `slopmop ev select` | prints the selected folder |
| `slopmop file list` | every file in the selected folder |
| `slopmop files ls` | the same, through the aliases |
| `slopmop file list -script` | only scripts |
| `slopmop file list -script -other` | two roles at once |
| `slopmop file list --evidence other/folder` | another folder for this call |
| `slopmop file list -o wide` | every column |
| `slopmop file list -q -script` | script names only, one per line |

## 5. Fails

| Command | Error |
| --- | --- |
| `slopmop bogus list` | `unknown noun "bogus"` |
| `slopmop file bogus` | `file has no verb "bogus"` |
| `slopmop file list -bogus` | `unknown selector -bogus (valid selectors: -other, -output, -script)` |
| `slopmop file list --role x` | `unknown option --role (valid params: --evidence <folder>)` |
| `slopmop file list --script` | `--script takes no value; "script" is a selector, use -script` |
| `slopmop file list -evidence x` | `-evidence takes a value; use --evidence <folder>` |
| `slopmop file list --evidence` | `--evidence needs a value <folder>` |
| `slopmop file list --evidence a --evidence b` | `--evidence given more than once` |
| `slopmop file list extra` | `file list expects no positional args, got 1` |
| `slopmop evidence select a b` | `evidence select expects 0 to 1 positional args, got 2` |
| `slopmop file list -o yaml` | `unknown view "yaml" (valid views: json, wide)` |
| `slopmop file list -q -o json` | `-q cannot be combined with -o` |
| `slopmop evidence select -q` | `-q applies only to verbs that print rows` |
| `slopmop file list` with nothing selected | ``no evidence folder: pass --evidence <folder> or run `slopmop evidence select <folder>` `` |

## 6. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success, including requested help |
| 1 | the command ran and failed |
| 2 | usage error: the command line does not fit the grammar |

Errors go to standard error as `error: <message>`. A message that carries a file name from the
evidence is escaped as described in the [output schema](02-Output-Schema.md).

## 7. Help

Help is generated from the registered nouns and each verb's spec, so it cannot drift from the
parser. `slopmop`, `slopmop help`, `slopmop -h` and `slopmop --help` list the nouns. `slopmop NOUN`
lists its verbs. `-h` or `--help` after a verb prints that verb's selectors, params and output flags.

```text
$ slopmop file list -h
usage: slopmop file list [selectors] [--params] [output flags]
list the files directly in the evidence folder

selectors (single dash, pick any; none = all):
  -other      any other file
  -output     an output a script produced
  -script     a script the agent wrote

params (double dash, take a value):
  --evidence  <folder>

output flags:
  -o wide|json    every column, or JSON
  -q              column 1 only, one per line
  --no-headers    no header row
  --tz local|utc  zone of displayed times (default utc)
```
