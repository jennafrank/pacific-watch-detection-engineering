# PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003: Password spray, always-on Linux

> **Historical record. Superseded by [v2 (draft)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v2.md).** This is the v1 analyst playbook as used in July 2026, built under v2 of the card. The wording is preserved from the original, with two changes for publication: em dashes are replaced with other punctuation, and one real attacker IP address in Block 5 is replaced with a documentation address (203.0.113.10). The live-since date is corrected to 2026-07-18, the deployment date.
>
> **Known defects in this version**, found in the [v3 conformance review](v3-conformance-review.md) and corrected in v2:
>
> 1. **Query B's stated limit is wrong.** It filters on `Successes > 0` with no requirement for preceding failures, so it *can* return successes without failures. What it cannot establish is how the credentials were obtained, or that a success was malicious.
> 2. **Neither verification query isolates the case.** Both aggregate seven days by `RemoteIP` across all hosts, so they can combine unrelated hosts and accounts, and Query B does not check that a success came *after* the attempts.
> 3. **Blocks 4 and 7 conflict.** Block 4 says zero successes means disposition and close; Block 7 says any external spray against a Tier A host promotes.
> 4. **Block 2 describes the trigger per source IP.** The rule counts distinct accounts per host; source addresses are context, not the grouping key.
> 5. **The conclusion is stated too definitely.** Many accounts with few attempts each is consistent with spraying, not proof of it, and "failure-to-success correlation by source IP is unambiguous" (Block 8) does not hold where addresses are shared.

## Block 1. Header

| Field | Value |
|---|---|
| Playbook ID | PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| Detection | PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| MITRE technique | T1110.003, Password Spraying (escalates to T1078 on success) |
| Client tier in scope | Tier A: always-on instructor-provided Linux host. Client is range leadership. |
| Author / Version / Status | Jenna Frank · v1 · Active |
| Detection live since / Last updated | 2026-07-18 · 2026-07-19 |

## Block 2. What this detection fires on

Fires when a single external source IP produces a high volume of failed logons against the always-on Linux host within a one-hour window, spread across several distinct accounts. It reads DeviceLogonEvents in Defender for Endpoint, not SecurityEvent; Event 4625 is not collected in this workspace.

The account breadth is the point. Many accounts with few attempts each is spraying; one account with many attempts is guessing, which is PASSWORDGUESSING-ALWAYSONLINUX-T1110.001. The tested ratio in this range separates them cleanly: roughly 96 attempts per account for guessing, roughly 2.5 for spraying.

## Block 3. Client tier and authority

This detection is scoped to the always-on Linux host, which is Tier A. It is range-provided, not participant-owned, and the Client is range leadership, a reachable, accountable owner. Full lifecycle applies: investigate, advise, record the outcome.

The SOC does not block the source IP, does not disable the targeted accounts, does not rotate credentials and does not modify the host. Not because observation is valuable, but because the SOC holds advisory authority and not remediation authority over range infrastructure. Those actions are the content of a Client Recommendation to range leadership, who decide and act.

## Block 4. Triage in sixty seconds

All four checks are answerable from the Alert Case description. Do not open Sentinel unless check 4 sends you there.

| # | Check | Decision |
|---|---|---|
| 1 | Is the source IP external? (SOC - Normalized Entities) | Private or in-VNet → likely another participant's asset or lab activity. Go to check 3. External → continue. |
| 2 | How many accounts, and how many attempts each? (description block) | Many accounts, few attempts each → spraying, consistent with this detection. One account, many attempts → wrong detection, likely a duplicate of PASSWORDGUESSING-ALWAYSONLINUX-T1110.001. Link and close as Duplicate. |
| 3 | Do the account names look like a wordlist, or like real accounts in this range? | Generic wordlist names (admin, root, test, oracle, ubuntu) → commodity internet noise. Names matching actual range accounts → higher concern, treat as targeted. |
| 4 | Did anything succeed? (description block, successful-logon count) | Zero successes → disposition and close, see Block 6. One or more successes → STOP. Promote now under criteria 1 and 2. Do not continue triaging. |

> [!IMPORTANT]
> Check 4 is the case. Everything before it establishes context; the success count decides the outcome. If you read nothing else in this playbook, read check 4.

## Block 5. Verification KQL

**Query A: confirm the spray shape and get the attempts-per-account ratio.** Tested 2026-07-12; returned 142 external attacking IPs across seven days.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where not(ipv4_is_private(RemoteIP)) and isnotempty(RemoteIP)
| summarize FailedAttempts = count(), AccountsTried = dcount(AccountName),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP
| where FailedAttempts > 20
| extend AttemptsPerAccount = round(FailedAttempts * 1.0 / AccountsTried, 1)
| sort by FailedAttempts desc
```

**Query B: did it work?** This is the promotion question. Tested 2026-07-12; returned 64 external IPs with at least one success, including 203.0.113.10 (documentation address; the real address is withheld) with eleven successful root logons on the Linux host.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| summarize Failures  = countif(ActionType == "LogonFailed"),
            Successes = countif(ActionType == "LogonSuccess"),
            Accounts  = dcount(AccountName) by RemoteIP
| where not(ipv4_is_private(RemoteIP)) and isnotempty(RemoteIP)
| where Successes > 0
| sort by Failures desc
```

An empty result from Query B means no successful logon from that source in the window. It does not mean the host is clean: a credential obtained by phishing, purchase or infostealer produces a successful logon with no preceding failures, and this query will not surface it.

## Block 6. Disposition guide

| Observed | Disposition | Model triage note |
|---|---|---|
| External IP, wordlist accounts, zero successes | True Positive – Malicious | Wordlist accounts from one external IP; no successful logon observed. Commodity internet brute force against an exposed host. Aggregated to the standing background-noise Campaign. |
| Any successful logon follows | True Positive – Malicious | Do not close. Promote; see Block 7. |
| Source IP internal to VNet and resolves to a participant's own second VM; account names match their test wordlist | True Positive – Authorized Participant Activity | Account names match the range participant's own test wordlist; source IP internal to the VNet and resolves to the owner's second VM. Owner-generated lab activity. No recommendation required. |
| Activity coincides with a scheduled threat-hunt exercise or a simulator run | True Positive – Authorized Simulated Activity | Timing and source match the staged exercise of [date]. Confirmed with the threat-hunt engineer. Excluded from threat metrics. |
| Rule fired but the underlying attempts are not failed logons | False Positive | Detection fired on activity that did not occur as characterised. Detection Improvement Request raised. Third FP on PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 in seven days. |
| Known scanner, expected, harmless in this environment | Benign Positive | Source is the in-VNet Tenable scan engine performing authorised scanning. Expected and harmless. Tuning candidate. |
| Cannot tell whether a logon succeeded; telemetry gap | Insufficient Evidence | DeviceLogonEvents coverage incomplete for this host in the window; cannot confirm or exclude a successful authentication. Infrastructure & Visibility Request raised. |
| Same source, same host, same hour, already ticketed | Duplicate | Same activity as SOCOPS-###. Linked and archived. |

Attribution to Authorized Participant Activity requires the owner's confirmation or clear evidence of ownership. Assumption is not attribution. If you believe it is a participant's own lab work but cannot show it, the disposition is Insufficient Evidence and the case promotes.

## Block 7. Promotion decision and escalation decision

Of the twelve criteria in Operational Standard 01 §13, these five realistically apply to PASSWORDSPRAY-ALWAYSONLINUX-T1110.003. Any one of them promotes. Note: escalation (Tier 1 → Tier 2 review) is a separate act from promotion (creates a Security Case).

| Criterion | Name | What triggers it here |
|---|---|---|
| 1 | Disposition is True Positive – Malicious | External spray against a Tier A host, regardless of success. |
| 2 | A successful objective follows | Any successful logon from the spraying source. This is the common promotion path. |
| 3 | More than one host or account involved | The same source IP appears against a second host in the same window. |
| 5 | Analyst cannot reach a confident disposition | You are unsure. Promote. Low confidence is a reason to escalate, never a reason to close. |
| 11 | Severity would be High or Critical | Successful root or administrative logon. |

## Block 8. If promoted

When you move the Alert Case to Promoted, an automation rule creates the Security Case, copies the description onto it, titles it Investigation - &lt;alert title&gt;, and links the two with a causes link. You do not create or link the case by hand. Refine the auto-generated title into investigation language (what you believe is happening, not which rule fired) and set the analytical fields below.

```text
Alert Case title      SOC-BUILD-PASSWORDSPRAY - linux-target-1 - 37 accounts
Security Case title   Credential compromise on always-on Linux host
                      following distributed password spray
```

| Field | Typical value on promotion |
|---|---|
| Disposition | True Positive – Malicious |
| SOC Severity | High where a successful logon occurred; Medium where not |
| Confidence | High: failure-to-success correlation by source IP is unambiguous |
| Complexity | Moderate |
| Client Tier | A (Client: range leadership) |
| MITRE technique | T1110.003 → T1078; set by hand at promotion. Copy from Block 1. The Logic App does not populate MITRE. |
| First Next Action | Enumerate post-authentication process and network activity on the host from the first successful logon onward; determine whether persistence was established. |
| Client Recommendation likely? | Yes. Tier A has a reachable Client, and this is the Phase 2 exit path for demonstrating the full advisory loop. |

## Block 9. Known false positives and environment gotchas

- Event 4625 is not collected here. A SecurityEvent-based version of this query deploys and never fires. Always use DeviceLogonEvents. (2026-07-12)
- The in-VNet Tenable scan engine produces authentication failures during authorised scanning. Check whether the source resolves to the scanner before dispositioning as malicious. (2026-07-12)
- An internal source IP is not automatically benign. The range is one shared VNet and participants can reach each other's assets. Confirm ownership; do not assume. (2026-07-15)
- Volume is high and mostly commodity. 142 external attacking IPs in a seven-day window is normal background for this environment. Per Charter §14.2, commodity internet noise against exposed hosts is aggregated into a standing Campaign and reported as a trend, not raised as individual cases. (2026-07-12)
- Query B cannot see credentials obtained without brute force. Phished, purchased or infostealer-sourced credentials produce a clean successful logon with no failure history. Absence of a failure-to-success pattern is not evidence of no compromise. (2026-07-12)
