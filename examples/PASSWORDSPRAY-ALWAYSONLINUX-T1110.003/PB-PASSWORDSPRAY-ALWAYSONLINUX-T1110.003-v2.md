# PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003: Password spray, always-on Linux (v2, draft)

> **Status: draft revision.** This corrects defects found in [v1](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v1.md) during the [v3 conformance review](v3-conformance-review.md). The verification queries below have **not yet been run in the range**; until they are, this revision does not meet the card's requirement that every published query is tested. What changed and why is listed in the [example README](README.md#what-changed-from-v1-to-v2).

## Block 1. Header

| Field | Value |
|---|---|
| Playbook ID | PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| Detection | PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| MITRE technique | T1110.003, Brute Force: Password Spraying (verified 2026-09-25). A successful logon may add T1078, Valid Accounts. |
| Client tier in scope | Tier A: always-on instructor-provided Linux host. Client is range leadership. |
| Author / Version / Status | Jenna Frank · v2 · Draft (pending retest) |
| Detection live since / Last updated | 2026-07-18 · 2026-09-25 |

## Block 2. What this detection fires on

Fires when `linux-target-1` records 8 or more distinct accounts in failed logons within one hour. The rule counts per host, not per source; source addresses are context in the alert, not the grouping key. It reads DeviceLogonEvents in Defender for Endpoint; Event 4625 is not collected in this workspace.

Many accounts with few attempts each is **consistent with** password spraying, which MITRE describes as trying one password or a small set of passwords across many accounts. The attempts-per-account ratio supports that reading but does not establish it: the logs do not show which passwords were tried, and several users or tools behind one shared address can produce the same shape. One account with many attempts points instead to password guessing (PASSWORDGUESSING-ALWAYSONLINUX-T1110.001).

## Block 3. Client tier and authority

This detection is scoped to the always-on Linux host, which is Tier A. It is range-provided, not participant-owned, and the Client is range leadership, a reachable, accountable owner. Full lifecycle applies: investigate, advise, record the outcome.

The SOC does not block the source IP, does not disable the targeted accounts, does not rotate credentials and does not modify the host. The SOC holds advisory authority, not remediation authority, over range infrastructure. Those actions are the content of a Client Recommendation to range leadership, who decide and act.

## Block 4. Triage in sixty seconds

All four checks are answerable from the Alert Case description. Do not open Sentinel unless check 4 sends you there.

| # | Check | Decision |
|---|---|---|
| 1 | Are the sources external? (source list in the description; the mapped IP entity is one arbitrary source, not the most frequent) | All private or in-VNet → likely another participant's asset, the Tenable scanner, or lab activity. Go to check 3. Any external → continue. |
| 2 | How many accounts, and how many attempts each? (description block) | Many accounts, few attempts each → consistent with spraying; continue. One account, many attempts → likely a duplicate of PASSWORDGUESSING-ALWAYSONLINUX-T1110.001. Link and close as Duplicate. |
| 3 | Do the account names look like a wordlist, or like real accounts in this range? | Generic wordlist names (admin, root, test, oracle, ubuntu) → consistent with commodity internet noise. Names matching actual range accounts → treat as targeted. Record which in the triage note. |
| 4 | Did anything succeed? (description block, successful-logon count) **Deciding check.** | One or more successes → STOP. Promote now under criteria 1 and 2. Zero successes, external source → True Positive – Malicious; promote under criterion 1 (Block 7). |

> [!IMPORTANT]
> **Block 7 governs promotion.** Any external spray against this Tier A host promotes under criterion 1, with or without a success. Check 4 decides how urgently, and which criteria apply, not whether to promote.

## Block 5. Verification KQL

Both queries are scoped to the case: the affected host and an explicit time window. The rule counts per host, so there may be several sources; the queries return all of them. Set the `let` values from the Alert Case before running.

**Query A: confirm the pattern on this host, by source.**
Test date and observed result: [FILL IN, not yet run]

```kql
let CaseHost    = "linux-target-1";               // DeviceName is an FQDN; match with startswith
let WindowStart = datetime(2026-01-01 00:00:00);  // alert window start, UTC
let WindowEnd   = datetime(2026-01-01 01:00:00);  // alert window end, UTC
DeviceLogonEvents
| where Timestamp between (WindowStart .. WindowEnd)
| where DeviceName startswith CaseHost
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count(),
            AccountsTried  = dcount(AccountName),
            Accounts       = make_set(AccountName, 100),
            FirstFailure   = min(Timestamp),
            LastFailure    = max(Timestamp)
            by RemoteIP
| extend AttemptsPerAccount = round(FailedAttempts * 1.0 / AccountsTried, 1)
| order by AccountsTried desc
```

**Query B: did any logon succeed on this host after the attempts began?**
Returns successes from any of the attempting sources, and successes from **any** source on an account that was tried, from the first failure to the end of the review window.
Test date and observed result: [FILL IN, not yet run]

```kql
let CaseHost    = "linux-target-1";
let WindowStart = datetime(2026-01-01 00:00:00);
let WindowEnd   = datetime(2026-01-01 01:00:00);
let ReviewEnd   = datetime(2026-01-02 00:00:00);  // extend past the alert window to catch later use
let Attempts = DeviceLogonEvents
    | where Timestamp between (WindowStart .. WindowEnd)
    | where DeviceName startswith CaseHost
    | where ActionType == "LogonFailed";
let FirstFailure    = toscalar(Attempts | summarize min(Timestamp));
let TriedAccounts   = Attempts | distinct AccountName;
let AttemptSources  = Attempts | distinct RemoteIP;
DeviceLogonEvents
| where Timestamp between (FirstFailure .. ReviewEnd)
| where DeviceName startswith CaseHost
| where ActionType == "LogonSuccess"
| where RemoteIP in (AttemptSources) or AccountName in (TriedAccounts)
| extend FromAttemptSource = RemoteIP in (AttemptSources),
         OnTriedAccount    = AccountName in (TriedAccounts)
| project Timestamp, AccountName, RemoteIP, FromAttemptSource, OnTriedAccount, LogonType
| order by Timestamp asc
```

**Visibility limits.** A row from Query B shows a successful logon on this host after the attempts began, from an attempting source or on a tried account. It does **not** establish how the credentials were obtained, that the success came from the same actor, or that it was malicious. Shared addresses and unrelated sessions can place legitimate and hostile activity on the same IP or account. An empty result means no such success is recorded in this window; it does not mean the host is clean, and it does not rule out a success outside the window or on an account that was not tried.

## Block 6. Disposition guide

| Observed | Disposition | Model triage note |
|---|---|---|
| External source, wordlist accounts, zero successes | True Positive – Malicious | Wordlist accounts from external source(s); no successful logon recorded on the host in the review window (Query B). Pattern consistent with commodity password spraying against an exposed Tier A host. Promoted under criterion 1. |
| A successful logon from an attempting source, or on a tried account, after the first failure | True Positive – Malicious | Do not close. Promote under criteria 1 and 2; see Block 7. Attribution of the success to the spraying actor is an inference; state its confidence and basis. |
| Source IP internal to VNet and resolves to a participant's own second VM; account names match their test wordlist | Authorized Participant Activity | Account names match the range participant's own test wordlist; source IP internal to the VNet and resolves to the owner's second VM. Owner-generated lab activity, confirmed with the owner. No recommendation required. |
| Activity coincides with a scheduled threat-hunt exercise or a simulator run | Authorized Simulated Activity | Timing and source match the staged exercise of [date]. Confirmed with the threat-hunt engineer. Excluded from threat metrics. |
| Rule fired but the underlying attempts are not failed logons | False Positive | Detection fired on activity that did not occur as characterised. Detection Improvement Request raised. |
| Known scanner, expected, harmless in this environment | Benign Positive | Source is the in-VNet Tenable scan engine performing authorised scanning. Expected and harmless. Tuning candidate. |
| Cannot tell whether a logon succeeded: telemetry gap | Insufficient Evidence | DeviceLogonEvents coverage incomplete for this host in the window; cannot confirm or exclude a successful authentication. Infrastructure & Visibility Request raised. |
| Same source, same host, same hour, already ticketed | Duplicate | Same activity as SOCOPS-###. Linked and archived. |

Attribution to Authorized Participant Activity requires the owner's confirmation or clear evidence of ownership. Assumption is not attribution. If you believe it is a participant's own lab work but cannot show it, the disposition is Insufficient Evidence and the case promotes.

## Block 7. Promotion decision and escalation decision

**This block governs promotion.** Block 4 follows it. Of the twelve criteria in Operational Standard 01 §13, these five realistically apply to PASSWORDSPRAY-ALWAYSONLINUX-T1110.003. Any one of them promotes (creates a Security Case). Escalation (Tier 1 → Tier 2 review) is a separate act from promotion.

| Criterion | Name | What triggers it here |
|---|---|---|
| 1 | Disposition is True Positive – Malicious | External spray against a Tier A host, regardless of success. |
| 2 | A successful objective follows | Query B returns a success from an attempting source, or on a tried account, after the first failure. This is the common promotion path. |
| 3 | More than one host or account involved | The same source IP appears against a second host in the same window. |
| 5 | Analyst cannot reach a confident disposition | You are unsure. Promote. Low confidence is a reason to escalate, never a reason to close. |
| 11 | Severity would be High or Critical | Successful root or administrative logon. |

## Block 8. If promoted

When you move the Alert Case to Promoted, an automation rule creates the Security Case, copies the description onto it, titles it Investigation - &lt;alert title&gt;, and links the two with a causes link. You do not create or link the case by hand. Refine the auto-generated title into investigation language (what you believe is happening, not which rule fired) and set the analytical fields below.

```text
Alert Case title      SOC-BUILD-PASSWORDSPRAY - linux-target-1 - 37 accounts
Security Case title   Suspected credential compromise on always-on Linux host
                      following a password spray pattern
```

| Field | Typical value on promotion | Set by |
|---|---|---|
| Disposition | True Positive – Malicious | Analyst, at promotion |
| SOC Severity | High where a successful logon occurred; Medium where not | Analyst, at promotion |
| Confidence | Set from the evidence, with its basis. A success from an attempting source on a tried account supports attribution; a shared or cloud address, or a success long after the attempts, weakens it. | Analyst, at promotion |
| Complexity | Moderate | Analyst, at promotion |
| Client Tier | A (Client: range leadership) | Analyst, at promotion |
| MITRE technique | T1110.003; add T1078 if a valid account was used. The Logic App does not populate MITRE. | Analyst, by hand at promotion |
| First Next Action | Enumerate post-authentication process and network activity on the host from the first successful logon onward; determine whether persistence was established. | Analyst, at promotion |
| Client Recommendation likely? | Yes. Tier A has a reachable Client. | Analyst |

## Block 9. Known false positives and environment gotchas

- Event 4625 is not collected here. A SecurityEvent-based version of this query deploys and never fires. Always use DeviceLogonEvents. (2026-07-12)
- The in-VNet Tenable scan engine produces authentication failures during authorised scanning. Check whether the source resolves to the scanner before dispositioning as malicious. (2026-07-12)
- An internal source IP is not automatically benign. The range is one shared VNet and participants can reach each other's assets. Confirm ownership; do not assume. (2026-07-15)
- Volume is high and mostly commodity. 142 external attacking IPs in a seven-day window is normal background for this environment. Per Charter §14.2, commodity internet noise against exposed hosts is aggregated into a standing Campaign and reported as a trend, not raised as individual cases. (2026-07-12) **This Tier A host is an exception:** every external spray against it promotes under Block 7 criterion 1. (2026-09-25)
- Shared addresses complicate attribution. NAT, VPN and cloud egress can put unrelated users behind one IP, so a failure and a success from the same address are not automatically the same actor. (2026-09-25)
- Query B cannot show how credentials were obtained. A credential from phishing, purchase or an infostealer produces a success with no failures from this source; Query B returns it only if it is on a tried account or from the case source, and cannot tell it apart from the spray. (2026-09-25)
