# Detection Register entry: PASSWORDSPRAY-ALWAYSONLINUX-T1110.003

> Documented with the v3 [register template](../../templates/detection-register-entry.md). The rule was built in July 2026 under v2 of the card.

## Identity

| Field | Entry |
|---|---|
| Detection ID | PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| Live rule name | SOC-BUILD-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003 |
| Builder | Jenna Frank (detection builder) |
| Date claimed | [FILL IN] |
| Owner | [FILL IN] |
| Status | Active since 2026-07-18 |
| Version | [FILL IN: query version] |

## Behavior and scope

| Field | Entry |
|---|---|
| Behavior to detect | A pattern consistent with password spraying: 8 or more distinct accounts in failed logons against one host in one hour |
| Named assets | `linux-target-1` (always-on, instructor-provided) |
| Client tier | Tier A. Client: range leadership |
| Source table | `DeviceLogonEvents` (Defender for Endpoint). Event 4625 is not collected. |

## MITRE mapping

| Field | Entry |
|---|---|
| Verified technique ID | T1110.003 |
| Technique name | Brute Force: Password Spraying |
| Source link | https://attack.mitre.org/techniques/T1110/003/ |
| Date verified | 2026-09-25 (verified for this write-up; the July verification is not recorded) |
| Reason it fits | MITRE describes spraying as one password or a small set tried across many accounts. The observable pattern here is account breadth: many accounts with few attempts each (roughly 2.5 attempts per account, against roughly 96 for guessing, T1110.001). The logs do not show which passwords were tried, so the mapping is an inference from that pattern. |

## Linked work

| Field | Entry |
|---|---|
| Query | [query.kql](query.kql): deployed query recovered 2026-09-25; version reference [FILL IN] |
| Baseline and threshold | [baseline-and-threshold.md](baseline-and-threshold.md) |
| Test results | Historical backtest recorded; lab replay, threshold-edge and data tests not recorded. See the [conformance review](v3-conformance-review.md). |
| Playbook | [v1 (historical)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v1.md); [v2 (draft)](PB-PASSWORDSPRAY-ALWAYSONLINUX-T1110.003-v2.md) |
| First genuine detection | 2026-07-19, `linux-target-1`: 101 attempts, 38 distinct accounts, 12 source addresses |
| Outstanding requests | [FILL IN] |

## Rule settings (as deployed)

| Setting | Value |
|---|---|
| Schedule and lookback | Every 1 hour, previous 1 hour |
| Behavior threshold | 8 or more distinct accounts per hour |
| Event grouping | Single alert |
| Incident alert grouping | Host, within 5 hours |
| Entities | Host (DeviceName); IP (`TopSource`, the first element of `SourceList`; not necessarily the most frequent source) |
| Custom details | Attempts, distinct accounts, source addresses |
| Query outputs | DeviceName, Attempts, Accounts, Sources, AccountList (max 20), SourceList (max 20), TimeGenerated, TopSource, ShortHost |
| Grouping key | Host. Source addresses are context, not the grouping key. |
| Severity | Medium |
| Suppression, reopen, automated response | [FILL IN] |
