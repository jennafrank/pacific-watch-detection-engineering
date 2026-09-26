# v3 conformance review: PASSWORDSPRAY-ALWAYSONLINUX-T1110.003

This is a **historical detection review with incomplete evidence**. The rule was the first production Pacific Watch detection, built in July 2026 under v2 of the card. This review grades it against every requirement in [v3.0](../../card/detection-build-card.md), using only what is recorded. The deployed query was recovered during this review (2026-09-25); the baseline dates and test evidence are still missing, so it grades the record, not the rule's tested behavior. Recovering that evidence comes first in the changes list below.

**Grades**

- **Met:** the record shows the requirement was satisfied.
- **Partially met:** some of the requirement is shown, not all of it.
- **Not met:** the record shows the requirement was not satisfied.
- **Not recorded:** no evidence either way. This is not a pass. Several of these may have happened and simply were not written down, which v3 treats the same as not done.

**Sources:** the rule facts in [register-entry.md](register-entry.md), the backtest in [baseline-and-threshold.md](baseline-and-threshold.md), and playbook [v1](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v1.md).

---

## 01. Start and research

| Requirement | Grade | Evidence |
|---|---|---|
| Technique claimed in the Detection Register before building | Not recorded | No register entry or claim date from July. |
| Scoped to named always-on assets or honeypots | Met | Scoped to `linux-target-1`, an always-on instructor asset. |
| Behavior researched; legitimate look-alikes identified | Partially met | The playbook distinguishes spraying from guessing (about 2.5 vs about 96 attempts per account) and names the Tenable scanner. It presents the ratio as establishing spraying; it supports it but does not prove it. Research sources are not recorded. |
| ATT&CK technique verified on the official site, with source link and reason | Partially met | T1110.003 is correct and the reason (account breadth) is stated. The July verification and source link are not recorded; verified again 2026-09-25 for this review. |

## 02. Reproduce and inspect

| Requirement | Grade | Evidence |
|---|---|---|
| Behavior reproduced in an authorized lab test, with tool, commands, target and times | Not recorded | The evidence is a historical backtest, not a lab replay. |
| Legitimate look-alike reproduced | Not recorded | The scanner and guessing patterns are described from observed data, not reproduced. |
| Evidence record: action and timing, primary, supporting, data quality, observed result | Not recorded | No evidence record exists. |
| Gaps treated as findings, with method | Partially met | Playbook Block 9 records that Event 4625 is not collected. Its note on Query B's limit is inaccurate: the query can return successes without failures; what it cannot establish is how credentials were obtained or whether a success was malicious. |

## 03. Build the query

| Requirement | Grade | Evidence |
|---|---|---|
| Scoped to approved assets, one-hour window, measured threshold | Met | `linux-target-1`, hourly over the previous hour, 8 or more distinct accounts from a measured baseline. |
| One row per subject that needs review | Met | The query summarizes `by DeviceName` and is scoped to one host. |
| Required output fields (DeviceName, primary count, evidence lists, `max(TimeGenerated)`, ShortHost) | Partially met | DeviceName, primary count (`Accounts`), event count (`Attempts`), distinct count (`Sources`), evidence lists, `TimeGenerated = max(TimeGenerated)` and `ShortHost` are all returned. The lists are capped at 20 and the cap is not recorded; the 2026-07-19 case tried 38 accounts. |
| Local query rules (no `has`/`has_any`, relative time, no `bin()` in the rule window) | Met | Uses `startswith`; no `has`/`has_any`, no fixed `datetime()`, no `bin()`; `TimeGenerated = max(TimeGenerated)` inside summarize. The window comes from the rule's lookback, not the query. |
| Exclusions reviewed with evidence and coverage cost | Partially met | The Tenable scanner is documented as a known false positive in the playbook, but the query has no scanner or private-source exclusion, so its failures count toward the threshold. No before-and-after counts. |
| Runnable query text and version saved in the register | Partially met | The deployed query was recovered on 2026-09-25 and is preserved in [query.kql](query.kql). It was not in the register at the time, and no version reference is recorded. |

## 04. Measure and validate

| Requirement | Grade | Evidence |
|---|---|---|
| Baseline measured and recorded: dates, scope, query, counts, distribution | Partially met | Baseline of 1 to 4 per hour against spike hours of 33 and 37. Dates, scope, query and distribution are not recorded. |
| Exact trigger specified | Met | `Accounts >= 8`: distinct accounts in failed logons, per host, in the rule's 1-hour window. (Playbook v1 described it per source IP; see Block 2.) |
| Legitimate look-alike named, with separating field and before-and-after counts | Partially met | Guessing, the scanner and participant lab activity are named with separating evidence. No before-and-after counts. |
| Known behavior test (lab replay and historical window) | Partially met | Historical window tested (33 and 37 accounts). No lab replay. |
| Normal activity test | Partially met | A baseline of 1 to 4 per hour is recorded. A test of the named look-alike is not. |
| Threshold edge tests (below, at, above) | Not recorded | |
| Data and context tests (delayed, missing, duplicate records) | Not recorded | |
| Retest after tuning | Not recorded | A "tuned rule" fired on 2026-07-18, so tuning happened. Retest results are not recorded. |
| Noise assessed with reviewed outcomes and sample size | Not recorded | The `SOC - Disposition` field was created 2026-07-18, so outcomes before then were not captured through it. |
| Queue capacity (3 to 5 per day, retune above 10) | Not recorded | This rule's observation window: not recorded at build time. For card-built rules generally, see the 2026-09-25 to 09-26 measurement [below](#other-rules-observed-under-the-card-2026-09-25-to-09-26-utc). |

## 05. Configure and enrich

| Requirement | Grade | Evidence |
|---|---|---|
| Schedule every 1 hour, lookback 1 hour | Met | Rule facts. |
| Alert threshold greater than 0, behavior threshold inside the query | Partially met | The behavior threshold (`Accounts >= 8`) is inside the query. The rule's alert threshold setting is not recorded. |
| Event grouping: single alert | Met | Rule facts. |
| Suppression off | Not recorded | |
| Incident creation enabled; test incidents do not create Jira cases | Partially met | Incidents are created. Test incidents were kept out of Jira by leaving the Logic App disconnected during the bake, not by SOC-TEST naming. |
| Incident alert grouping: Host only, within 5 hours | Met | Rule facts. |
| Reopen closed match off; automated response empty | Not recorded | |
| Entities: Host mandatory using FullName; Account and IP from single-value fields | Partially met | Host is mapped from DeviceName; v3 asks for FullName. IP is mapped from `TopSource = tostring(SourceList[0])`: a single value, but `make_set()` does not guarantee order, so it is an arbitrary source rather than the top one, and the choice is not explained. No Account mapping. |
| Custom details include every required output field | Partially met | Custom details carry attempts, distinct accounts and source addresses, and the first tuned alert produced a correctly populated Alert Case (SOCOPS-320, 2026-07-18). ShortHost and the latest event time are not recorded as outputs. |
| Custom details verified in ExtendedProperties on an actual alert | Partially met | Verified in practice through SOCOPS-320. An ExtendedProperties inspection is not recorded. |
| Routing boundary: SOC-TEST in rule name and title during testing | Not recorded | The rule deployed as SOC-BUILD on 2026-07-18. Whether it ran under a SOC-TEST name first is not recorded. |
| Collection delay and time-boundary misses measured | Not recorded | |

## 06. Observe and release

| Requirement | Grade | Evidence |
|---|---|---|
| At least 48 hours of unchanged observation | **Not met** | The planned 48-hour alerts-only bake was shortened so the pipeline could be validated end to end. The Logic App was connected on 2026-07-18, the deployment day. |
| Release review items (volume, alert contents, title, readiness) | Partially met | Alert contents shown by SOCOPS-320. Volume and title review not recorded. |
| Independent query review by a second analyst | Not recorded | No reviewer, date, findings or fixes. |
| Register complete | Not met | Query text, baseline dates and test results are missing. |
| Naming pattern | Partially met | The rule name matches `SOC-BUILD-<TECHNIQUE>-<SCOPE>-<TID>` and the playbook ID matches `PB-<Detection ID>`. The source document is titled PB-SOC-001, an older ID. |
| Release by the named authority, with approval date | Not recorded | |
| First live alert reached Jira once; rollback method documented | Partially met | SOCOPS-320 reached Jira on 2026-07-18. "Once" and a rollback method are not recorded. |

## 07. Work a case

| Requirement | Grade | Evidence |
|---|---|---|
| At least one real Alert Case worked start to finish | Not recorded | SOCOPS-327 (2026-07-19) is a real case, and the playbook was updated the same day. The end-to-end handling is not recorded. |
| All nine blocks present | Met | Blocks 1 to 9 are present. |
| Block 1: header fields | Met | All fields present. Live-since date corrected to the 2026-07-18 deployment for publication. |
| Block 2: trigger with a concrete threshold | Partially met | Plain-language trigger and separating evidence are present. It says "a high volume" instead of the number 8, and describes the trigger per source IP instead of per host. |
| Block 3: scope and authority | Met | Tier A, Client named, advisory authority stated, remediation excluded. |
| Block 4: three to five checks, answerable from the case, deciding check marked | Partially met | Four checks; check 4 marked as the deciding check. Its instruction to close on zero successes conflicts with Block 7. |
| Block 5: two tested queries, observed result, test date, visibility limits | Partially met | Queries A and B tested 2026-07-12 with results. Neither is scoped to the case host, source or time window; both aggregate seven days by source IP across all hosts. Query B does not check that a success followed the attempts, and its stated limit is inaccurate. |
| Block 6: all seven dispositions with model triage notes | Met | All seven covered, with notes. The labels use a "True Positive" prefix that the current field values do not. |
| Block 7: promotion and escalation stated separately; criterion 5 included | Partially met | Five criteria including criterion 5; escalation and promotion distinguished. Criterion 1 promotes any external spray against a Tier A host, which conflicts with Block 4. |
| Block 8: Security Case fields and who sets them | Partially met | Fields and typical values listed. "Who sets it" is stated for MITRE only. The confidence guidance ("failure-to-success correlation by source IP is unambiguous") overstates attribution where addresses are shared. |
| Block 9: false positives and gaps, dated | Met | Five entries, each dated. |
| No playbook step grants authority the analyst does not hold | Met | Block 3 excludes blocking, disabling, credential rotation and host changes. |
| Simulation authorization from a reliable record | Met | Block 6 requires confirmation with the threat-hunt engineer and states that assumption is not attribution. |

## 08. Review and maintain

| Requirement | Grade | Evidence |
|---|---|---|
| First-minute checks timed under 60 seconds on a real case | Not recorded | |
| Second analyst works a different case using the playbook alone | Not recorded | |
| Process & Documentation, Operations Lead and index reviews | Not recorded | |
| Every published query tested in the range, with result and date | Met | Queries A and B, 2026-07-12. |
| Maintenance: owner, next review, volume and freshness limits | Not recorded | |
| Changes versioned with reason and coverage effect | Partially met | Playbook v1 with a last-updated date. Rule and query versions are not recorded. |

## 09. Environment facts

| Requirement | Grade | Evidence |
|---|---|---|
| Failed-logon work uses DeviceLogonEvents (Event 4625 not collected) | Met | Playbook Blocks 2 and 9. |
| An internal IP is not treated as benign | Met | Playbook Block 9 (2026-07-15). |
| Scanner noise validated before exclusion | Partially met | Tenable documented as a known source; the exclusion is not recorded. |

---

## Other rules observed under the card, 2026-09-25 to 09-26 UTC

Not graded above; recorded here as open findings so they are not hidden. 17 alerts across 6 rules, 2026-09-25 to 09-26 UTC (09-26 partial), 1 host per alert:

| Rule | Alerts |
|---|---|
| DEFEVADE-REGMOD-T1112 | 9 |
| INGRESSTOOLTRANSFER | 3 (2 hosts) |
| IMPACT-RANSOMNOTE-T1491.001 | 2 |
| NETWORKSERVICEDISCOVERY | 1 |
| PERSIST-RUNKEY-T1547.001 | 1 |
| DISCOVERY-ACCTENUM-T1087 | 1 |

**Open findings**

1. **DEFEVADE-REGMOD-T1112 fired 9 times on 2026-09-25.** That is above the card's 3 to 5 alerts per rule per day target and below the retune threshold of 10. It needs a volume and outcome review.
2. **NETWORKSERVICEDISCOVERY and INGRESSTOOLTRANSFER break the v3 naming pattern.** Their names carry no technique ID, and they use an em dash separator. The card requires `SOC-BUILD-<TECHNIQUE>-<SCOPE>-<TID>` with hyphens only.

---

## Summary

| Grade | Count |
|---|---|
| Met | 18 |
| Partially met | 25 |
| Not met | 2 |
| Not recorded | 20 |
| **Total requirements graded** | **65** |

What the record does show: the rule was scoped to a named always-on asset, built on the table that actually carries this data, and set from a measured spike. The recovered query follows the local query rules and returns one row per host, but maps its IP entity to an arbitrary source, caps its evidence lists at 20 without recording it, and has no scanner exclusion. What the record cannot show is whether the rule works as intended, because the baseline dates and test evidence are missing. The review also found defects in the analyst guidance: verification queries that do not isolate the case, an inaccurate statement of Query B's limits, conflicting promotion instructions, and a spraying conclusion stated more firmly than the evidence allows. [Playbook v2](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v2.md) is a draft correction; it has not been retested.

## Changes required before this rule would pass v3

1. **Recover the rest of the evidence first.** The deployed query is recovered (2026-09-25). Still missing: a version reference for it, the backtest spike date, and the baseline dates, scope, query and count distribution. Until these exist, this stays a historical review.
2. **Fix the query findings.** Make `TopSource` the most frequent source (for example with `arg_max` over a per-source count) or rename and explain it; record the 20-entry list cap or raise it; decide the scanner and private-source exclusion with before-and-after counts; exclude empty `AccountName` values.
3. **Apply the promotion policy**: Block 7 governs, so any external spray against a Tier A host promotes, regardless of success. Playbook v2 aligns Block 4 to it, and records this Tier A host as an exception to the Charter §14.2 Campaign rule.
4. **Run and record the corrected verification queries** from playbook v2, scoped to the case host and time window, with test date and observed result.
5. **Run the missing detection tests** and record them: an authorized lab replay of a spray, a replay of the look-alikes (guessing and the scanner), threshold edges at 7, 8 and 9 accounts, and delayed or duplicate record checks.
6. **Write an evidence record** for the lab test using the v3 template.
7. **Map Host with FullName**, and add an Account mapping only if the query returns a valid single value.
8. **Rerun as SOC-TEST** for at least 48 unchanged hours with test incidents kept out of Jira, and record daily alert counts against the 3 to 5 per day target with reviewed outcomes for each.
9. **Get an independent query review**: a second analyst reruns the query and tests, with reviewer, date, findings and fixes recorded.
10. **Release through the named authority** with a recorded approval date, confirm the first live alert reaches Jira once, and document the rollback method.
11. **Test the playbook** under 60 seconds on a real case and with a second analyst on a different case, then complete the Process & Documentation, Operations Lead and index reviews.
12. **Assign maintenance**: named owner, next review date, alert-volume and data-freshness limits, and the response when either is crossed.
