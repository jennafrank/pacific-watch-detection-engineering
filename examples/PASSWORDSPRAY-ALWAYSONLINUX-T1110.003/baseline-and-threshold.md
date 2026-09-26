# Baseline and threshold: PASSWORDSPRAY-ALWAYSONLINUX-T1110.003

## Trigger

Alert when `linux-target-1` records **8 or more distinct accounts** in **failed logons** in **one hour** (`Accounts >= 8` in the [deployed query](query.kql)). The rule runs every hour over the previous hour.

The rule counts **per host**, not per source. Source addresses are context in the alert (custom details carry attempts, distinct accounts and source addresses), not the grouping key. Playbook v1 described the trigger per source IP; v2 corrects it.

## Backtest

| Hour (UTC) | Distinct accounts |
|---|---|
| 10:00 | 33 |
| 11:00 | 37 |
| Baseline | 1 to 4 per hour |

- **Spike date:** [FILL IN]
- **Baseline dates, scope and query:** [FILL IN]
- **Count distribution:** [FILL IN]

The spike hours sat roughly an order of magnitude above the baseline. The threshold of 8 is above the baseline maximum (4) and well below both spike hours (33, 37).

## Distinguishing the look-alikes

These distinctions support a disposition; none of them is conclusive on its own.

| Look-alike | What distinguishes it | Source |
|---|---|---|
| Password guessing (T1110.001) | Attempts per account: roughly 96 for guessing, roughly 2.5 for spraying | Playbook Block 2 |
| In-VNet Tenable scan engine | Source resolves to the scanner | Playbook Block 9 (2026-07-12) |
| A participant's own lab activity | Source internal to the VNet, resolves to the owner's second VM, owner confirms | Playbook Block 6 |

Before-and-after counts for each filter: [FILL IN]

## Observed alert volume

16 alerts in 48 hours [FILL IN: which 48-hour window, in UTC] [CONFIRM: from this rule, not the password guessing rule]. That is about 8 per day: inside the card's 1 to 10 local review band, above the 3 to 5 per day workload target, and below the retune point of 10 per day. Reviewed outcomes for those 16 alerts are not recorded.

## First genuine detection

2026-07-19, `linux-target-1`: 101 attempts, 38 distinct accounts, 12 source addresses. 38 accounts is above the threshold of 8 and just above the larger backtest hour (37).
