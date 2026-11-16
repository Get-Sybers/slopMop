# Agent and contributor guide

Read this before changing anything. These rules bind every contributor and every AI agent.

## Rules

1. **Branches are deleted when merged.** The author of a merged branch deletes it.
2. **Comments in code are minimal and concise.** A comment gives a reason the code cannot. No
   banner comments, no comment that restates the code, no block longer than three lines.
   `make structlint` rejects a longer block.
3. **Docs state fact only.** A document describes what the repository does now, in the present
   tense. No plan, status, intention or history. `make structlint` rejects plan and status wording
   and tick boxes in `README.md`, `AGENTS.md` and `docs/`.
4. **Changes are tracked in `CHANGELOG.md` and nowhere else.** Every change adds a line under
   `## [Unreleased]`. No tracking marker in code, no progress note in a document.

## Before a commit

```sh
make conform
```

The gate is described in [docs/04-Conformance.md](docs/04-Conformance.md). Nothing merges red.

## Where things live

| To change | Edit |
| --- | --- |
| a noun, verb, alias, summary or column | `internal/command/nouns.json`, then the verb's implementation |
| a role, its extensions or shebang patterns | `internal/inventory/roles.json` |
| the grammar or an error message | `internal/cli` and [docs/01-Command-Grammar.md](docs/01-Command-Grammar.md) |
| how a value prints | `internal/render` and [docs/02-Output-Schema.md](docs/02-Output-Schema.md) |
| how evidence is read | `internal/inventory` and [docs/03-Architecture.md](docs/03-Architecture.md) |
| a golden file | `make golden-update`, then read the diff |
| a linter or Go version | `.pre-commit-config.yaml`, `go.mod` |

## Code

- Go standard: `docs/04-Go-Standards.md` in the VelociSacci repository.
- A static table is a data file, embedded and validated at load, never a literal in a `.go` file.
- Names state the work: `Read`, `Load`, `Check`, `List`, `Run`, `Classify`, `Detect`. No `Get`.
- Tests use the standard library only, are table-driven, and compare with golden files.
- Evidence is attacker-controlled text. It is never executed, never written to, and escaped before
  it reaches a terminal.
- British spelling in prose and comments.
