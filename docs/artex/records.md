# ARTEX records

What ARTEX itself writes down about its work: the files it leaves, the format of each, and the
vocabulary of the graph they describe. Read from the 12 checkouts listed in [report.md](report.md),
as data; nothing in them was run. `n/12` is the number of checkouts that carry the item. Source
paths are relative to a checkout, and their lines are those of `BaaRai_ARTEX` at 278de8b unless a
fork is named.

Formats of the SDK (section 3) are read from the two checkouts that vendor it (norma v0.4.3,
`third_party/norma/`); the lines given for the SDK are those of `icebergn2026_artex-ld` at 6bc4c1e.
The other ten use norma v0.3.4, v0.3.8, v0.4.3, v0.4.4 or v0.4.10 without carrying its source, so
the same formats are assumed for them.

## 1. The intent number

`i<N>` is `exploration_nodes.id`, a `BIGSERIAL` (`db/schema.sql:171`). Goals, intents, facts,
findings, hints and digests share that one table, so the number is database-wide: it is shared by
every task on the instance and only increases. It records when the intent row was created, not
when the intent ran. A gap between two intents is a node of another kind or of another task. The
row also holds `payload` (JSON), `priority`, `state`, `origin`, `owner`, `blocked_reason`,
`delete_reason`, `created_at`, `updated_at` and `completed_at`.

Where the number is written:

| Place | Source |
| --- | --- |
| run folder `<data>/tasks/<task>/i<N>/` | `agent/worker.go:317` |
| session name `exp<E>-worker-i<N>`: the transcript file, the sidechain folder, `noa/<session>/` and `session:` in each archive | `agent/worker.go:101` |
| the worker's first user message: the intent text, then `Intent id: <N> (pass it when writing back record_fact / report_finding)` | `agent/worker.go:357` |
| `intent_id` in the input of `record_fact` and `report_finding` (worker) and of `kill_work`, `steer_work`, `get_worker_output`, `get_worker_trace` (planner) | `agent/tools.go:1575, 1402, 1916, 1947, 1981, 2062` |
| `exploration_nodes.id`, and the `tables` of a task archive | `db/schema.sql:171` |

- `<task>` is the task id and `<E>` the exploration id. They are different numbers; `manifest.json`
  of a task archive holds both.
- Open intents are listed by priority, highest first, then by number (`db/exploration.go:1195`),
  and a worker claims the first one it can in that order (`server/engine.go:1391`). An intent with
  a higher priority can therefore run before one with a lower number.
- The worker's system prompt gives the absolute path of its run folder, tells it to write scripts,
  payloads, captured response bodies and temporary data there and not in `/tmp`
  (`agent/worker.go:308`), and its working directory is that folder (`:515`). The planner and the
  main agent work in `<data>/tasks/<task>/` itself (`:313`).
- In the prompt code of `agent/` the number appears in the write-back instructions of the worker
  and in the planner's trace-reading instructions (`worker.go:261-262, 358`,
  `promptcatalog.go:112`). No line there asks the model to put the number in a name, prefix or
  label, so a name that carries `i<N>` on a target or inside a script is the model's choice.
- The session name and the run folder are functions of the ids alone (`worker.go:101, 317`), so a
  rerun uses the same ones. The code states that the intent id is the session identity so that a
  later message resumes the same conversation (`worker.go:97-100`); after a `model_error` the whole
  intent reruns (ARTEX's `CHANGELOG.md:672`). One `i<N>` folder or transcript can cover more than
  one run.

## 2. Data folder

The `-data` flag defaults to `data/` next to the executable (`cmd/artex/main.go:53`).

| Path under `data/` | n/12 | Holds |
| --- | --- | --- |
| `tasks/<task>/i<N>/` | 12 | what a worker wrote: scripts, payloads, response bodies |
| `tasks/<task>/` | 12 | files of the planner and main agent |
| `<run folder>/cmd-output/` | 12 | tool output too long for the model (section 3) |
| `transcripts/` | 12 | one JSONL file per session (section 3) |
| `noa/<session>/` | 10 | archived conversation blocks (section 3) |
| `archives/tasks/task-<task>-<archive>.tar.zst` | 12 | a task packed for cold storage (section 6) |
| `traffic/_index/index.sqlite`, `traffic/_blobs/sha256/` | 12 | the recording proxy's exchanges (section 7) |
| `traffic/_ca/mitmproxy-ca-cert.pem` | 12 | certificate authority of the recording proxy |
| `evidence/` | 11 | the evidence store (`server/finding_traffic.go:23`) |
| `.tools/` | 12 | custom tools (`server/customtool.go:496`) |

`findings.zip` (11/12) is built in a staging folder when an operator downloads findings as a zip
(`server/server.go:2383`).

## 3. Files the SDK writes

**Transcript.** `transcripts/<session>.jsonl`; a sub-agent writes
`transcripts/<session>/subagents/agent-<id>.jsonl` (`transcript/transcript.go:61, 66`). One JSON
object per line, appended: `uuid`, `parent_uuid`, `session_id`, `agent_id`, `is_sidechain`,
`timestamp`, `type` (`message` or `boundary`), `message`, `usage`, `boundary` (`:37`). A message
has `role` and `content`; a content block is `text`, `thinking`, `tool_use` (`id`, `name`,
`input`) or `tool_result` (`tool_use_id`, `content`, `is_error`) (`llm/types.go`).

- Each line gets a new `uuid`, the previous line's `uuid` as `parent_uuid`, and the time of the
  write as `timestamp`, UTC with nanoseconds (`:200-208`).
- After a compaction the boundary marker, the summary and the kept recent messages are written
  again; the kept messages also exist earlier as originals (`:8-14`). The copies have new `uuid`s
  and the time of the compaction as `timestamp`; the earliest copy carries the time of the
  original. Clearing of old tool results is not written to disk (`:15-17`).

**Spilled tool output.** A tool result longer than 30,000 bytes (`len` of the text,
`tool/helpers.go:12, 31-34`) is written whole to `cmd-output/output-<unix seconds>-<n>.txt` in the
run folder (`:81`), and the model receives the first 30,000 bytes followed by this (the sizes and
the name are examples):

```
... <persisted-output>[Output too large: full 41233 bytes / 812 lines.Full output saved to  cmd-output/output-1763369472-7.txt </persisted-output>
```

The format has two spaces before the path and no closing bracket (`:46`); the path is relative to
the working directory when it lies inside it (`:38-41`). `<n>` is one counter for the whole process
(`:21`), starting at 1 on each start. Without a configured folder the result is cut to head and
tail with a notice containing `characters truncated]`, and the rest is discarded. Workers set the
folder (`agent/worker.go:531`).

**Context archive.** `noa/<session>/tier<k>/b<block>_<first>-<last>.md` and
`noa/<session>/state.json` (`noa/archive.go:204, 209`, `noaadapter/state_store.go:80`). Front
matter keys: `block`, `tier`, `session` and `created` (each written only when set), `range`,
`consumed_blocks`, `loose_messages`, `message_count`, `original_tokens`, `topic`. The archive
holds the original messages verbatim (`:54-58`). `noa` is present in the ten checkouts that pin
norma 0.4 or later and absent from the two that pin 0.3. It is written only when a setting
enables it; when it is off or fails to start, the built-in compaction runs instead
(`agent/noa.go:32-60`).

## 4. Session names

| Name | n/12 | Session |
| --- | --- | --- |
| `exp<E>-planner` | 12 | the planner; one accumulating file per task (`agent/planner.go:572`) |
| `exp<E>-worker-i<N>` | 12 | the worker of intent N (`agent/worker.go:101`) |
| `exp<E>-main` | 12 | the main agent, first segment (`agent/mainagent.go:172`) |
| `exp<E>-main-s<k>` | 11 | the main agent, segment k ≥ 1, one file each (`:178`) |
| `exp<E>-goals` | 10 | goal decomposition requests (`agent/goals.go:124`) |
| `exp<E>-compactor` | 10 | digest compression requests (`agent/compaction.go:96`) |
| `exp<E>-btw-<id>` | 11 | a side question (`server/side_questions.go:431`) |

A side question is filed under the key of its parent (`sidequestion/capture.go:25-33`):
`conv-<id>` for a platform conversation (11/12), `task-<T>-exp-<E>-worker-i<N>` for a worker
(11/12), `task-<T>-exp-<E>-main` for the main agent (11/12).

## 5. Graph vocabulary

Node kinds (`db/schema.sql:186`): `begin` (12/12, deprecated: a new task seeds a fact in state
`origin` instead, `db/constants.go:5`), `goal`, `intent`, `fact`, `finding`, `hint` (12/12),
`digest` (11/12). Edge relations in `exploration_edges`: `spawns`, `derived_from`, `yields`,
`proves` (12/12) and `covers` (11/12; digest to member, `db/constants.go:39`).

| Kind | States |
| --- | --- |
| intent | `open`, `running`, `paused`, `done`, `blocked`, `exhausted`, `stopped`, `deleted`; `proposed` in `icebergn2026_artex-ld` only |
| goal | `open`, `met`, `abandoned` |
| fact | `confirmed`, `dismissed`, `origin` |
| finding | `confirmed`, `dismissed` |
| hint | `active`, `consumed` |
| digest | `active`, `superseded` |

ARTEX's changelog defines three of the intent states (`CHANGELOG.md:726`): `exhausted` is
the step or time budget cut off midway with partial results written back, not a direction fully
explored; `blocked` is model, API or network failures that used up their retries so the intent
barely ran, not interception by the target; `stopped` is a work stopped by the user. `kill_work`
sets `stopped` (`agent/tools.go:1916`).

A fact carries `confidence` (`observed`, `inferred`) and `source`: `target_response` (content the
target itself returned, such as page bodies, headers, error messages, banners), `tool_output` (a
tool's own result about the target, such as port states, scanner verdicts, status codes, timings),
`third_party_intel`, `operator_input`, and `inference` (the default). `prove_goal` refuses a fact
as evidence unless its confidence is `observed` and its source is not `target_response`
(`agent/tools.go:1305`). Finding severity is `critical`, `high`, `medium` or `low`; the triage
status of a finding is `pending`, `in_progress`, `confirmed`, `fixed` (11/12), `resolved`,
`ignored`, `false_positive`, `duplicate` or `risk_accepted` (`db/findings.go:47-55, 70-73`).

## 6. Task archive

`archives/tasks/task-<task>-<archive>.tar.zst` (`server/task_archive_package.go:88`). Its
`manifest.json` is a `TaskArchiveSnapshot` (`db/task_archives.go:134`): `format_version`,
`created_at`, `task_id`, `exploration_id`, `source_task_ids`, `hosts`, `exclusive_hosts`,
`exclusive_asset_ids`, `tables` (small tables as JSON arrays), `streamed_tables`, `data_counts`,
`aggregate_stats`. The tables include `exploration_nodes`, `exploration_edges`,
`exploration_anchors` (node to asset), `findings`, `finding_traffic_bindings`,
`traffic_evidence_snapshots` and `assets` (`db/task_archives.go:597-616`). The restore code moves
`files/tasks/<task>/` back to `tasks/<task>/` and every file of `files/transcripts/` back to
`transcripts/` (`task_archive_package.go:230-250`); no `noa` path appears in
`task_archive_package.go` or `db/task_archives.go`.

## 7. Recording proxy

`traffic/_index/index.sqlite` (`traffic/traffic.go:41`):

- `exchanges`: `id`, `ts`, `host`, `method`, `url_template`, `url`, `status`, `content_type`,
  `req_len`, `resp_len`, `path`. `ts` is Unix seconds (`:508`); `id` is `<unix seconds>-<4 digits>`
  (`:555`).
- `exchange_bodies`: `req_head`, `req_body`, `req_blob`, `resp_head`, `resp_body`, `resp_blob`.
  A body of up to 256 KiB is stored in the column; a larger one is written to
  `traffic/_blobs/sha256/<first two hex digits>/<hash>.bin`, and the row keeps a short preview and
  the hash (`:111, 578-615`).
- `blob_refs` (`hash`, `exchange_id`) and `stream_messages` (WebSocket and SSE messages in arrival
  order). The file also carries a trigram text index (`:273`).

## 8. Tools that write results back

These calls appear as `tool_use` blocks in the transcript of the session that made them. Fields
are those of the input schema; `[]` marks a batch array whose items repeat the top-level fields.

| Tool | n/12 | Fields | Records |
| --- | --- | --- | --- |
| `add_intent` | 12 | `intents[]`, `summary`, `asset_ids`, `parent_ids`, `priority` (0-10, default 5); `chain_tags` in one fork | a direction: what and why, the assets it targets, the fact or finding ids it derives from |
| `record_fact` | 12 | `facts[]`, `summary`, `detail`, `evidence`, `confidence`, `source`, `intent_id`, `asset_ids`; `topology` in one fork | a conclusion, positive or negative, tied to its intent; `evidence` is one line |
| `report_finding` | 12 | `vulnclass`, `name`, `severity`, `summary`, `intent_id`, `asset_ids`, `evidence`, `evidence_hint_id`, `traffic_refs`, `counterevidence`, `confidence_rationale` | a vulnerability the worker states it triggered, with reproducible evidence (`agent/worker.go:262`) |
| `insert_assets` | 12 | `assets` | sites, endpoints, parameters, hosts |
| `add_hint` | 12 | `hints[]`, `text`, `asset_ids`, `traffic_refs` | a hint the planner reads when it next generates intents, stored with its origin: `human` for the main-agent chat, `orchestrator`, or the agent's name (`agent/tools.go:1854`) |
| `set_goals` | 12 | `goals[]`, `text`, `vulnclass` | a final, verifiable result |
| `set_constraints` | 12 | `constraints[]`, `text`, `type` (`allow`, `deny`; default `deny`) | rules on which operations may run |
| `prove_goal` | 11 | `goal_id`, `evidence_id`, `reason` | a goal marked met by a fact or finding |
| `goal_met` | 11 | `reason` | the whole task ended as complete |
| `kill_work` | 12 | `intent_id` | an intent stopped; not re-claimed automatically |
| `steer_work` | 12 | `intent_id`, `message` | an instruction delivered before the worker's next action |
| `get_worker_output`, `get_worker_trace` | 12 | `intent_id`; `q`, `step_ids`, `limit` | the planner reading a worker's steps |
| `update_finding_report` | 12 | `finding_id`, `report`, `evidence_version`, `poe_level`, `evidence_quotes` | the write-up of a finding |
| `bind_finding_traffic` | 11 | `finding_id`, `traffic_refs` | recorded exchanges attached to a finding |
| `save_task_credential` | 1 | `domain`, `username`, `password`, `note` | a test account the agent registered on the target (`agent/tools_creds.go:18`) |
| `record_credential` | 1 | `asset_id`, `cred_type`, `username`, `domain`, `secret`, `target`, `source`, `extra` | a credential |
| `mark_credential_verified` | 1 | `credential_id`, `asset_id`, `target`, `evidence` | a credential confirmed to work |
| `record_coverage` | 1 | `surface`, `risk_area`, `outcome`, `evidence`, `reason` | a coverage ledger entry |

The checkouts register 80 tools through `writeTool`, `readTool` and their `Exp` variants. The
others read the graph (`list_*`, `get_*`, `search_*`), manage the platform or a task, or exist in
only one or two forks (`cancel_intent`, `set_intent_status`, `confirm_fact`).

## 9. Not recorded in these files

- The names a model gives to things it creates on a target, and the text of its scripts, are its
  own choices; no file of the framework lists them.
- The database is not a file in the data folder. Its graph reaches the folder only inside a task
  archive.
- The SDK formats are read from one version. The others are not read.
