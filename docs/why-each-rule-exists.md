# Why each rule exists

Every local rule in the [Detection Build Card](../card/detection-build-card.md) traces to something that broke or something we learned. This file records what happened and how the card now prevents it.

---

## 1. No `has` or `has_any` for host matching

**What happened:** the always-on Linux target reports its device name as a fully qualified name (`linux-target-1.<hash>...`). A `has_any` match on the host name failed because of how KQL tokenizes the hyphenated name. `startswith` and `contains` matched.

**How the card prevents it:** section 03 requires `contains`, `startswith` or `matches regex` for substring and pattern matching, excludes `has` and `has_any` in local rules, and requires testing the exact host names you intend to match.

## 2. The threshold sits inside the query, measured from a baseline

**What happened:** the first password spray rule was backtested against a known spike: 33 and 37 distinct accounts in the spike hours, against a baseline of 1 to 4 per hour. That measurement set the threshold at 8 or more distinct accounts per hour.

**How the card prevents guessing:** section 04 requires running the measurement query without its threshold over a representative baseline, recording the distribution, and specifying the exact counted item, comparison, number, grouping and window. Section 05 puts the behavior threshold inside the query, with the rule firing on greater than 0 results. No threshold is approved from intuition alone.

## 3. A rare action can alert on one occurrence

**What happened:** the event log clearing detection (T1070.001) uses a threshold of 1, because there is no distribution to baseline against. It is deployed range-wide with a documented reason, and some fires are expected to be Authorized Participant Activity.

**How the card handles it:** section 04 allows one matching occurrence to be the threshold for a defined rare action, while still requiring an assessment of legitimate uses. Section 03 requires a documented reason and review for whole-range scope.

## 4. Test rules stay out of Jira: SOC-TEST vs SOC-BUILD

**What happened:** unthresholded test rules reached the case queue. Alert volume ran at roughly 286 to 293 per day from Jul 12 to 15, 2026, and produced 316 Jira cases. See [case study 01](https://github.com/jennafrank/cyber-range-soc/blob/main/docs/case-studies/01-queue-flood-316-cases.md).

**How the card prevents it:** section 05 keeps every test rule outside the Jira case-creation route. Test rules use SOC-TEST in both the rule name and alert title, and the builder verifies that no Jira case is created. Section 06 lets only the named release authority change SOC-TEST to SOC-BUILD, after at least 48 hours of observation.

## 5. Custom details must be verified on a real alert

**What happened:** Sentinel custom details arrived in the Logic App as a JSON string with single-element arrays. Fields came through blank until they were parsed correctly.

**How the card prevents it:** section 05 requires verifying counts, evidence lists, names and time values on an actual alert, and inspecting ExtendedProperties to confirm the expected custom fields arrived. Section 06 makes "custom details present in ExtendedProperties" a release review item.

## 6. Use Device* tables and check coverage per host

**What happened:** participant VMs do not send Windows Security Event data to Sentinel. Defender Device* tables are the viable source, so failed-logon work goes to `DeviceLogonEvents`.

**How the card prevents it:** section 09 records "Event 4625 is not collected" and "Defender Device* tables are primary" as environment facts to recheck, and requires confirming onboarding, required fields and current data arrival for each scoped host. Section 02 requires confirming the table is populated and the tested action appears before writing logic.

## 7. Named always-on assets, not temporary participant machines

**What happened:** participant hostnames churn. Detections scoped to them go stale or noisy.

**How the card prevents it:** section 01 requires named always-on assets or honeypots and says not to depend on temporary participant machines. Section 09 repeats it as an environment fact.

## 8. Confirm simulation authorization from a reliable record

**What happened:** scripted Active Directory enumeration first looked like a participant's account. It was confirmed as a staged exercise directly with the scenario owner and dispositioned as Authorized Simulated Activity.

**How the card prevents a wrong disposition:** section 07 requires confirming simulation authorization from a reliable record ("resemblance alone is insufficient"), labeling authorization separately from false positives, and excluding authorized simulations from threat metrics.
