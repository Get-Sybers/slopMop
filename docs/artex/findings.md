# ARTEX findings, in detail

This expands on `report.md`. Everything below comes from reading the 12 checkouts as
data (no code was run) and checking each claim against the source file and line in
`facts.tsv`. Where a thing was reported earlier but not re-checked here, that is said
plainly.

## 1. What was read

12 checkouts of ARTEX and its forks, at the commits in the table below. The upstream
`Autumn-27/ARTEX` and a second copy, `trhhubsd/ARTEX`, are both deleted on GitHub, so
none of the 12 is "the original" — they are mirrors and forks taken after the fact.

| checkout | commit | skills |
|---|---|---|
| BaaRai_ARTEX | 278de8b | 10 |
| Core-RCE_ARTEX-original-version | 2bea670 | 3 |
| Hinln_ARTEX | f3e3f54 | 3 |
| RuoJi6_ARTEX | 6997a46 | 3 |
| Xiao1an_ARTEX-God | 68e9f1f | 7 |
| bdg9412_artex-ko-plus | 556495c | 4 |
| cskwork_scopeweaver | e894337 | 3 |
| failsafe-security_artex | fd6376c | 3 |
| icebergn2026_artex-ld | 6bc4c1e | 3 |
| jiwoochris_artex-global | 133f3cf | 3 |
| panda0x123_artex-ymh | 48adc7f | 12 |
| yes-chen_ARTEX | 081f7dc | 3 |

`cskwork_scopeweaver` is a rename, not a different design: the generator found it on
its own, because most of its environment-variable suffixes match ARTEX's own
(`SCOPEWEAVER_PG_DSN` against `ARTEX_PG_DSN`, and so on). No one told it the name.

## 2. What is structurally stable

Two things are unchanged in all 12 checkouts, regardless of branding:

- **The run folder**, `tasks/<task>/i<intent>`, where a worker drops its output for one
  planner intent. `<intent>` is the literal id, not zero-padded (`i7`, `i4028`, never
  `i0007`).
- **The session key format**, `exp<N>-...`: `exp%d-planner`, `exp%d-main`, and
  `exp%d-worker-i%d` are in every checkout. `conv-%d`, `exp%d-btw-%s`, `exp%d-main-s%d`
  and `task-%d-exp-%d-main` are in 11 of 12 (the one exception in each case is a
  different fork each time, not the same outlier fork throughout).

`<intent>`'s `i` prefix is not a convention the prompts specify. It is the BIGSERIAL
primary key of one Postgres table (`exploration_nodes` in the schema seen directly in
`bdg9412_artex-ko-plus/db/schema.sql`) that also numbers facts, findings, hints and
digests. So the id only ever goes up within one database, is not reset per task, and
has gaps wherever the agent created something else first. Two different intents named
`i4028` from two different incidents are not necessarily the same step of the same
playbook — they just both happened to be the 4028th row written to that table.

`task-%d-exp-%d-worker-i%d` is not a worker's own session id. It is the key under which
the side questions (`/btw`) that an operator asks about a worker are filed
(`sidequestion/capture.go` and `sidequestion/README.md` in the forks that have them). A
worker's own session is `exp%d-worker-i%d`.

`cmd-output` recurs under the run folders: it holds the tool output that was too long for
the model. `noa` is not a run-folder name: it is the folder of the data directory where
the SDK archives the context of a conversation when a setting enables it (10 of 12
checkouts carry it; see [records.md](records.md)).

## 3. What varies by fork

### Environment variables

72 environment-variable names total. Only **3** are in all 12: `ARTEX_CONFIG`,
`ARTEX_PG_DSN`, `ARTEX_SKILL_DIR`. The other 69 are fork-dependent — added, renamed, or
dropped by whoever forked the code. `facts.tsv` lists every one with its first file
and line. Matching on the 3 universal names plus the shape `(ARTEX|SCOPEWEAVER)_[A-Z0-9_]+`
(what `ArtexEnvVar` does) catches both the stable core and a fork's own additions,
without needing a fork-by-fork list.

### User agents

`artex-enrich/1.0` is the asset-enrichment probe's UA, and it is in the code of 10 of
12 forks (it is absent from the other 2's source — not just unseen by the scanner).
`norma/0.4` is a second, separate UA living in `third_party/norma/tool/webfetch.go` in
the 2 forks that vendor that fetch helper. Two more UAs, `AegisLoop-RSS/1.0` and
`AegisLoop-PublicResearch/1.0`, are fork additions in `bdg9412_artex-ko-plus` only —
they are not ARTEX's own and are kept in `watchlist.weak.json`, not the main list, so
they do not get attributed to ARTEX if they turn up elsewhere.

### The guard / control-framing marker

All 12 forks write some translation of the same control-framing string to a log when a
tool call is blocked. The Chinese original, `【ARTEX 平台管控·非目标防御】`, is in 8 of
12. The remaining 4 each carry a localised or re-branded variant: English in
`BaaRai_ARTEX`, English and Korean variants in the two ScopeWeaver-family forks, and a
lowercase `artex` variant in `icebergn2026_artex-ld`. The string's function (marking
that a refusal was platform-level control, not a defensive action by the target) is
constant; its exact text is not, so match it as one of a small fixed set rather than a
single literal.

### Paths

`/opt/artex/skills` is the one install path common to almost all forks (11 of 12). The
remaining `/opt/...`, `/etc/...` and `/opt/splunk/etc/apps/artex_lab/...` paths are each
seen in only 1–2 forks; the Splunk path is specific to the `bdg9412_artex-ko-plus`
detection-lab add-on, not the ARTEX runtime itself.

## 4. Strings seen in incident write-ups that are in no checkout

`artex-pentest/1.0`, `artex-readonly/1.0`, `artex-audit/1.0`, `artex-verify/1.0`,
`artex-spawn/1`, `ReconProbe/1.0`, `azure-toolkit/1.0`, and `artex-wtest` do not appear
anywhere in any of the 12 checkouts' source, prompts, or docs. The most likely
explanation is that an agent generated them at runtime (worker UAs and markers are
built from format strings with model-filled segments in several forks), or that they
came from a 13th build not in this sample. Either way, there is nothing to pin as a
literal: `ArtexUserAgent` and `ArtexToken` are shape patterns precisely so these still
register as hits even though their exact text was never in the harvested set.

`ARTEX-worker/1.0` is a special case: it is real text, but only inside
`web/src/lib/mock/data.ts`, the Next.js UI's mock fixture data, in every one of the 12
checkouts that has that file. One fork's changelog states outright that this string is
example UI text and is never sent over the network. I would not use it as evidence a
host ran ARTEX.

## 5. Comparison against a fork's own hand-built detections

`bdg9412_artex-ko-plus` ships its own detections folder with Sigma rules and a 7-row
indicator CSV (`detections/indicators/artex_indicators.csv`), written by that fork's
maintainers, not generated. Checking the generator's output against it line by line:

| their row | in the generated output? |
|---|---|
| `artex-enrich/1.0` (UA) | yes — `ArtexUserAgent` |
| `artex-selfupdate` (token) | yes — `ArtexToken` |
| `【ARTEX 平台管控·非目标防御】` (marker) | yes — `ArtexMarker` |
| default server port `8787` | no |
| loopback MITM recording proxy `127.0.0.1:8788` | no |
| MITM CA file `mitmproxy-ca-cert.pem` | no |
| Postgres table `exploration_nodes` | no |

The 3 matches are exactly the kind of fact the generator is built for: literal strings
written into source that stay put across a fork. The 4 misses are not an oversight —
they are host-side forensic leads, not strings that occur in a codebase for a text
scanner to extract:

- A listen port and a loopback proxy endpoint are run-time configuration (both are
  overridable by a command-line flag in the code I read), checked on a live host with
  `ss`/`netstat`, not by matching a string.
- `mitmproxy-ca-cert.pem` is also used, verbatim, by the unrelated standalone
  `mitmproxy`/`go-mitmproxy` tools, so the fork's own CSV already marks it as a
  triage lead rather than a unique fingerprint, and `to_ids` is off for it in their
  Sigma rule.
- `exploration_nodes` is a database table name, checked by querying the host's
  Postgres instance, not by scanning files on disk or packets on the wire.

None of these four are things a static-source generator should try to emit as
string indicators; they would need a different kind of collector (one that queries a
running host or a packet capture) and are called out here so the gap is explicit
rather than silent.

## 6. Two things found while reading that did not make it into any generated list

These are not watchlist material, but are worth having on file given what you are
building slopMop for.

**A built-in evidence-cleanup agent.** `icebergn2026_artex-ld` (only this one fork of
the 12) ships a `trace_cleaner` agent with its own default prompt
(`agent/trace_cleaner.go`). Read plainly, it is scoped to deleting the *tester's own*
scratch files from the target host at the end of an authorised engagement, not target
data, and its prompt requires it to post a plan in chat and wait for the operator to
reply "同意清理" ("agree to clean up") before running any delete — the file's own
comment says this confirmation is a conversation-level constraint the prompt asks for,
not something the platform enforces by itself. For DFIR purposes the practical point
is: a host that ran this build of ARTEX may have had its own attack-staging files
removed by the framework itself, as designed, which is a reason evidence can be thin
even without a human doing manual anti-forensics — and, because the control is only a
prompt, a modified or jailbroken deployment is not bound by it.

**Exploitation chains spelled out in a fork's own skill prompts.** `panda0x123_artex-ymh`
is the only one of the 12 with `chains-web` and `chains-priv` skills, whose reference
docs (e.g. `skills/chains-web/refs/web-to-shell.md`, `web-xxe.md`, `web-waf-bypass.md`)
walk through `php://filter` wrapper chains for reading PHP source via LFI, `data://`
and `php://input` for RCE where `allow_url_include` is set, and `phar://` combined with
deserialization. This is prompt content telling the planner how to exploit `php://`
stream wrappers, not a static string or indicator slopMop could watch for — it is listed
here as a gap (you asked about decode support earlier; this is the one exploitation
technique in the sample that is prompt-only and has no matching entry in slopMop's
decoders), not as something the generator should output.

## 7. Flagged but not verified

A separate claim that `darkfibr/artex-forensics` documents a backdoored Docker image
for ARTEX was mentioned in earlier research but that repository was never fetched or
read in this pass — it is not reflected in any file in this bundle, and should be
treated as unconfirmed until someone checks it directly.

## 8. A speculative inference, flagged as such

Because the `i<N>` id is the shared primary key of one database table per ARTEX
*instance* (not per task), the range of intent ids seen in two incidents could, in
principle, say something about whether those incidents share an instance (close
ranges) or clearly do not (ranges that are far apart or that overlap despite different
timestamps, which an id sequence cannot do). This is an inference from how the schema
works, not something confirmed against real incident data in this exercise, and it
only works at all if you already have the id from more than one incident to compare —
it is offered as a possible correlation signal to test, not a finding.

## 9. Caveats that apply to the whole bundle

- A watchlist hit scores `high` in slopMop, same as a hit on real attacker
  infrastructure. Everything in `watchlist.json` is a framework fingerprint (it shows
  *that* ARTEX ran), not an indicator of a specific attacker or campaign.
- Coverage is bounded by the 12 checkouts read. A fork not in this set, or a later
  commit of one that is, can add or drop any of the above.
- Model-written runtime strings (section 4) are only ever caught by shape, never by an
  exact-value watchlist entry — `reachable()` in the generator enforces this by
  dropping any pinned value its own pattern cannot re-extract, rather than shipping a
  watchlist entry that would silently never match.
