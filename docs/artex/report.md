# ARTEX harvest

Read 12 checkouts as data; nothing in them was run. Brand prefixes found: ARTEX, SCOPEWEAVER.

## Checkouts

| checkout | commit | run folder | worker session | env names by prefix | user agents | skills |
|---|---|---|---|---|---|---|
| BaaRai_ARTEX | 278de8b | yes | yes | ARTEX 29 |  | 10 |
| Core-RCE_ARTEX-original-version | 2bea670 | yes | yes | ARTEX 8 | artex-enrich/1.0 | 3 |
| Hinln_ARTEX | f3e3f54 | yes | yes | ARTEX 12 | artex-enrich/1.0 | 3 |
| RuoJi6_ARTEX | 6997a46 | yes | yes | ARTEX 13 |  | 3 |
| Xiao1an_ARTEX-God | 68e9f1f | yes | yes | ARTEX 12 | artex-enrich/1.0 | 7 |
| bdg9412_artex-ko-plus | 556495c | yes | yes | ARTEX 19 | AegisLoop-PublicResearch/1.0, AegisLoop-RSS/1.0, artex-enrich/1.0 | 4 |
| cskwork_scopeweaver | e894337 | yes | yes | ARTEX 11, SCOPEWEAVER 4 | artex-enrich/1.0, norma/0.4 | 3 |
| failsafe-security_artex | fd6376c | yes | yes | ARTEX 11 | artex-enrich/1.0 | 3 |
| icebergn2026_artex-ld | 6bc4c1e | yes | yes | ARTEX 13 | artex-enrich/1.0, norma/0.4 | 3 |
| jiwoochris_artex-global | 133f3cf | yes | yes | ARTEX 16 | artex-enrich/1.0 | 3 |
| panda0x123_artex-ymh | 48adc7f | yes | yes | ARTEX 35 | artex-enrich/1.0 | 12 |
| yes-chen_ARTEX | 081f7dc | yes | yes | ARTEX 10 | artex-enrich/1.0 | 3 |

## Structure that survives forks

| kind | value | checkouts | slopMop intent rules |
|---|---|---|---|
| rundir | `tasks/<task>/i<intent>` | 12/12 | covered by `run folder` |
| session | `exp%d-` | 12/12 | no intent in the name |
| session | `exp%d-main` | 12/12 | no intent in the name |
| session | `exp%d-planner` | 12/12 | no intent in the name |
| session | `exp%d-worker-i%d` | 12/12 | covered by `session` |
| session | `conv-%d` | 11/12 | no intent in the name |
| session | `exp%d-btw-%s` | 11/12 | no intent in the name |
| session | `exp%d-main-s%d` | 11/12 | no intent in the name |
| session | `task-%d-exp-%d-main` | 11/12 | no intent in the name |
| session | `task-%d-exp-%d-worker-i%d` | 11/12 | not covered |
| session | `exp%d-compactor` | 10/12 | no intent in the name |
| session | `exp%d-goals` | 10/12 | no intent in the name |
| session | `task-%d-exp-%d-main-s%d` | 1/12 | no intent in the name |

Rules slopMop lacks: 1 (see paths.add.json).

## Strings

| kind | value | checkouts |
|---|---|---|
| marker | `【ARTEX 平台管控·非目标防御】` | 8/12 |
| marker | `[ARTEX platform control, not target defense]` | 1/12 |
| marker | `[ScopeWeaver platform control, not target defense]` | 1/12 |
| marker | `[ScopeWeaver 플랫폼 제어, 대상 방어 아님]` | 1/12 |
| marker | `【artex 平台管控·非目标防御】` | 1/12 |
| path | `/opt/artex/skills` | 11/12 |
| path | `/opt/artex` | 2/12 |
| path | `/etc/artex.env` | 1/12 |
| path | `/etc/logrotate.d/artex` | 1/12 |
| path | `/etc/systemd/system/artex.service` | 1/12 |
| path | `/opt/artex-backups` | 1/12 |
| path | `/opt/artex/artex` | 1/12 |
| path | `/opt/artex/artex.log` | 1/12 |
| path | `/opt/scopeweaver/skills` | 1/12 |
| path | `/opt/splunk/etc/apps/artex_lab/default` | 1/12 |
| path | `/opt/splunk/etc/apps/artex_lab/metadata` | 1/12 |
| path | `/opt/splunk/etc/apps/artex_lab/metadata/default.meta` | 1/12 |
| token | `artex-selfupdate` | 7/12 |
| token | `artex-update-check` | 1/12 |
| token | `scopeweaver` | 1/12 |
| token | `scopeweaver-selfupdate` | 1/12 |
| ua | `artex-enrich/1.0` | 10/12 |
| ua | `norma/0.4` | 2/12 |
| ua | `AegisLoop-PublicResearch/1.0` | 1/12 |
| ua | `AegisLoop-RSS/1.0` | 1/12 |

Environment names: 3 in every checkout, 69 in some (facts.tsv lists them).

Values left out of the watchlists because their own pattern cannot extract them: `scopeweaver`

Subfolders the agents create under a run folder (in at least half the checkouts): `cmd-output`, `noa`

## Strings seen in incidents, traced to the checkouts

| string | code | agent prompt or skill | prose or mock data | verdict |
|---|---|---|---|---|
| `artex-pentest/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `artex-readonly/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `artex-audit/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `artex-verify/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `artex-spawn/1` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `ARTEX-worker/1.0` | 0/12 | 0 | 12 | prose or mock data only |
| `artex-enrich/1.0` | 10/12 | 0 | 1 | in code |
| `ReconProbe/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `azure-toolkit/1.0` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `norma/0.4` | 2/12 | 0 | 3 | in code |
| `artex-wtest` | 0/12 | 0 | 0 | in no checkout: written by the model, or by another build |
| `example.invalid` | 2/12 | 0 | 0 | in code |
| `/opt/artex` | 11/12 | 0 | 0 | in code |
| `artex-update-check` | 1/12 | 0 | 0 | in code |
| `artex-selfupdate` | 7/12 | 0 | 1 | in code |
