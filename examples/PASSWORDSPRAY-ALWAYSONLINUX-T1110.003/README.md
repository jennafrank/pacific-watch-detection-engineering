# Worked example: PASSWORDSPRAY-ALWAYSONLINUX-T1110.003

**A historical detection review with incomplete evidence.** The first production Pacific Watch detection, built in July 2026 under v2 of the card, graded here against v3 and corrected where the review found defects.

## The behavior

The rule watches `linux-target-1`, an always-on instructor Linux host, for 8 or more distinct accounts in failed logons in one hour in `DeviceLogonEvents` (per the deployed query recovered 2026-09-25). Alerts below the documented threshold on Jul 18 to 19; cause not recorded. Many accounts with few attempts each is consistent with password spraying (T1110.003), which MITRE describes as trying one password or a small set across many accounts. The pattern supports that reading; it does not prove it.

## Available evidence

| Evidence | Status |
|---|---|
| Rule settings (schedule, threshold, grouping, entities, severity) | Recorded in [register-entry.md](register-entry.md) |
| Backtest: 33 and 37 accounts in spike hours vs a baseline of 1 to 4 | Recorded in [baseline-and-threshold.md](baseline-and-threshold.md); spike date and baseline details missing |
| First genuine detection, 2026-07-19: 101 attempts, 38 accounts, 12 sources | Recorded |
| This rule's alert volume during observation | Not recorded at build time |
| Card-built rules generally: 17 alerts across 6 rules, 2026-09-25 to 09-26 UTC (09-26 partial) | Recorded; this rule is not among the six |
| Analyst playbook v1 with two verification queries, run 2026-07-12 | [v1 (historical)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v1.md) |
| Deployed rule query | Recovered 2026-09-25, preserved verbatim in [query.kql](query.kql); version reference missing |
| Lab replay, threshold-edge tests, independent review | Not recorded |

## Findings

The [v3 conformance review](v3-conformance-review.md) grades 66 requirements: 19 met, 24 partially met, 3 not met, 20 not recorded. The three not met are the shortened observation period, the incomplete register, and alerts below the documented threshold on Jul 18 to 19 (cause not recorded). Reading the recovered query found four more issues: the IP entity maps to an arbitrary source (`SourceList[0]`), the evidence lists are capped at 20 without recording it, there is no scanner or private-source exclusion, and empty account names are not filtered. The review also found five defects in the v1 playbook:

1. **Query B's stated limit was wrong.** It filters on `Successes > 0` with no requirement for preceding failures, so it can return successes without failures. What it cannot establish is how credentials were obtained or whether a success was malicious.
2. **The verification queries did not isolate the case.** Both aggregated seven days by source IP across every host, so unrelated hosts and accounts could combine, and Query B did not check that a success followed the attempts.
3. **Two blocks gave conflicting instructions.** Block 4 said close on zero successes; Block 7 said any external spray against a Tier A host promotes.
4. **Block 2 described the trigger per source IP.** The rule counts per host.
5. **The conclusion was too definite.** The ratio was treated as establishing spraying, and source-IP correlation was called "unambiguous" even though shared addresses can break attribution.

## What changed from v1 to v2

| v1 (July 2026) | Defect | v2 (draft) |
|---|---|---|
| Queries A and B aggregate seven days by `RemoteIP`, all hosts | Do not isolate the case | Both scoped to the case host and an explicit window, returning every attempting source |
| Query B: `Successes > 0` per source | Does not check order; stated limit inaccurate | Returns successes after the first failure, from an attempting source or on a tried account; limits restated accurately |
| Block 4 closes on zero successes; Block 7 promotes any Tier A spray | Conflicting instructions | Block 7 governs: any external spray against a Tier A host promotes, regardless of success. Block 4 now agrees. |
| Block 2 describes the trigger per source IP | Does not match the rule, which counts per host | Trigger stated per host, with the number (8); sources are context |
| "Many accounts, few attempts each → spraying" | Inference stated as fact | "Consistent with spraying," with the limits of the inference |
| Confidence: "failure-to-success correlation by source IP is unambiguous" | Overstates attribution | Confidence set from the evidence, with shared addresses named as a weakness |
| Disposition labels prefixed "True Positive" | Do not match current field values | Current `SOC - Disposition` values |
| "Who sets it" stated for MITRE only | Block 8 incomplete | Set-by column for every field |

## Outstanding

- **Recover the rest of the evidence**: the query's version reference, the spike date, and baseline dates and scope. This is the top priority.
- **Fix the query findings**: `TopSource` ordering, the 20-entry list cap, the scanner exclusion, empty account names.
- **Retest**: run the v2 verification queries in the range and record the test date and observed result. Until then, v2 is a draft and the chain from original to corrected ends before the retest.
- The rest of the changes list is at the end of the [conformance review](v3-conformance-review.md#changes-required-before-this-rule-would-pass-v3).

## Reading order

1. [register-entry.md](register-entry.md): what the rule is
2. [baseline-and-threshold.md](baseline-and-threshold.md): how the threshold was set
3. [PB v1 (historical)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v1.md): the playbook as used
4. [v3-conformance-review.md](v3-conformance-review.md): the grade, and what it found
5. [PB v2 (draft)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v2.md): the correction
6. [query.kql](query.kql): the deployed query and the historical verification queries, with findings noted
