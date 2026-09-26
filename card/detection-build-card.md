# Pacific Watch Detection Build Card

**Detection engineering / v3.0**

> Markdown version of [detection-build-card.pdf](detection-build-card.pdf). The wording is the card's own. Conversion notes are at the end of this file.

---

## 01 / Start and research

# Detection build card

Build one detection from observed behavior. Give another analyst the evidence and instructions to use it.

This card guides work in the Pacific Watch security operations center (SOC). A detection is a tested rule that identifies defined behavior in recorded activity. A playbook is the analyst’s written response guide. Complete both, or document why the available data cannot support the detection.

### Claim the work

Claim the technique in the Detection Register before building. Check the sign-up tracker for existing work. Record the fields below and keep the register current. Use named always-on assets or honeypots, which are systems set up to observe suspicious activity. Do not depend on temporary participant machines.

| Register field | Required entry |
|---|---|
| Identity | Detection ID, builder, date claimed, owner, status and version. |
| Behavior and scope | Behavior to detect, named assets, client tier and source table. |
| MITRE mapping | Verified technique ID, name, source link and reason it fits. |
| Linked work | Query version, evidence, test results and PB-&lt;Detection ID&gt;. |

### Research the behavior before writing the rule

Describe what the attacker does and what result matters. Read primary research, relevant tool code and product documentation. Identify the expected action, the records it might produce, and legitimate activity that may look similar. Treat expected records as a test plan until the lab confirms them.

MITRE ATT&CK is a catalog of adversary behaviors. Select the technique that matches the observed mechanism. Verify its current ID and name on the official site. Do not map a technique from a tool name alone or claim full technique coverage from one test. If no technique fits, record that finding and ask the Detection Engineering Lead to review the scope.

### Prepare access and guidance

Confirm query access to Microsoft Sentinel and Defender for Endpoint. Read Charter §12 and Operational Standard 01 (OS-01) §§13 to 14. Obtain Jira SOCOPS access from the Operations Lead before working live cases. The supported tools are Sentinel, Defender, Jira and a browser. Record any missing capability as an Infrastructure & Visibility Request.

> [!NOTE]
> Working record: Detection ID __________ Builder __________<br>
> Named release authority __________ Review date __________

The sequence is research, lab test, log inspection, query, positive tests, normal-activity tests, added context, analyst guidance, independent review, controlled release and maintenance. The detailed guides govern local settings. Report conflicts to the Operations Lead before release.

---

## 02 / Reproduce and inspect

# Prove what the logs show

Test the behavior in a controlled lab. Build from the records that actually arrive.

### Reproduce the behavior

Use approved lab assets and an authorized test. Record the tool and version, exact commands, configuration, test account, target and expected outcome. Save the start and end time, cleanup steps and evidence location. Reproduce the legitimate look-alike as well as the attacker behavior.

Telemetry means recorded activity from systems and security tools. Inspect the original records before writing detection logic. Confirm the table is populated, the relevant fields exist, and the tested action appears. Record differences between the action you ran and the values stored in the logs.

| Evidence record | What to capture |
|---|---|
| Action and timing | Test ID, action, asset and start/end in YYYY-MM-DD HH:MM:SS UTC. |
| Primary evidence | Table or log, event time, field name, exact value and saved query or raw-record reference. |
| Supporting evidence | Second table or source, matching identifiers and time relationship. State when it is unavailable. |
| Data quality | Collection settings, arrival delay, missing fields, retention and any clock offset. |
| Observed result | What was recorded, what was absent and what the evidence cannot establish. |

### Keep facts separate from interpretation

State the finding. Show the evidence. Then explain what it means. Assign High, Medium or Low confidence only to an inference, with its basis. Facts such as a timestamp or field value do not need confidence labels. Corroborate key findings with a second source. External research supplies context; it does not replace local evidence.

Use one attack clock throughout. Explain any difference between event time and stored time once, and state which timestamp the query filters. Preserve query text and raw log lines in code blocks. Distinguish the count measured during the test from a count across the wider environment.

### Treat gaps as findings

A negative result needs a method: name the table, fields, assets, time range and query that returned no matching rows. An empty table cannot prove the behavior did not occur. Name unexplained differences and missing visibility. Use “not established from available telemetry” when that is the supported conclusion.

> [!IMPORTANT]
> If the data cannot distinguish the target behavior, stop release. Record the gap in the register, raise an Infrastructure & Visibility Request and notify the Detection Engineering Lead. Link it in playbook Block 9. Continue independent work or claim another technique.

---

## 03 / Build the query

# Turn evidence into a rule

Kusto Query Language (KQL) is the query language used here to search and summarize security records.

A hunt query explores activity. A detection query selects a defined, actionable condition. Scope it to the approved assets, use the one-hour rule window, apply a measured threshold and return one row per subject that needs review. Whole-range scope needs a documented reason and review.

### Return the fields an analyst needs

The Logic App is the workflow that carries alert data into Jira. It can pass only the fields the rule supplies. KQL summarize groups records and keeps only the fields you specify. Preserve evidence lists as well as counts. Use the actual field names in the register and ticket mapping.

| Output | Purpose |
|---|---|
| Asset / DeviceName | The affected host. Map it to the Host entity using FullName. |
| Primary count | The number tested against the threshold, with its unit. |
| Event count | Total matching records for context. |
| Distinct count | A second count, such as unique source addresses, when useful. |
| Evidence lists | Observed accounts, sources, file paths or commands. Record any list-size limit. |
| TimeGenerated | Latest event time, retained within summarize using max(). |
| Single values | A scalar is one value. Supply a meaningful single account or IP address for mapping, where available. |
| ShortHost | Short host name used in the alert title. |

### Apply the local query rules

Use contains, startswith or matches regex for the required substring or pattern matching. The local authoring standard excludes has and has_any. Those operators match terms rather than arbitrary substrings; they are not universally invalid KQL. Test the exact host names and command fragments you intend to match.

Use relative time in a deployed rule. Fixed datetime() values belong in historical tests only. Do not use bin() to split the local rule window. Retain TimeGenerated = max(TimeGenerated) inside summarize. Test all fields after grouping. A list produced by make_set() cannot serve as a single mapped identity; extract and explain a representative value with tostring() when appropriate.

Review activity from senseir.exe, mssense.exe, mpcmdrun.exe, gc_worker.exe and known scanner accounts. Preserve the required local exclusions with evidence of the legitimate process, account and context. A filename alone does not prove benign activity. Record the coverage lost by each exclusion and send overbroad exclusions for review.

> [!IMPORTANT]
> Save runnable query text and a version reference in the register. Another analyst must be able to rerun the same logic and understand why each filter exists.

---

## 04 / Measure and validate

# Show what separates the signal

A true positive matches the intended behavior. A false positive alerts on activity outside that intended target.

### Measure normal activity and set an exact trigger

Run the measurement query without its threshold over a representative baseline, meaning normal activity used for comparison. Include relevant working hours, maintenance and scheduled jobs. Record the dates, scope, query, event counts and count distribution. Explain any period or asset group the baseline does not cover.

Specify the counted item, comparison, number, grouping and time window. For example: “Alert when one host records at least 20 distinct target accounts in one hour.” This is an illustration, not an approved threshold. Replace it with a number supported by your measurements and tests. For a defined rare action, one matching occurrence may be the threshold; still assess legitimate uses.

### Name the legitimate look-alike

Document the normal account, process, scanner or job that resembles the behavior. Identify the field and value that separate it from the target. If several conditions are needed, state each one. Show before-and-after counts for each filter. Record the exclusion’s reason, owner, review date and missed behavior it could hide.

| Test | Evidence required |
|---|---|
| Known behavior | Replay the authorized lab action and test a known historical window. Record expected and observed matches. Explain every miss. |
| Normal activity | Test the legitimate look-alike and a representative quiet window. Record returned rows and investigate unexpected alerts. |
| Threshold edges | Test just below, at and above the threshold. Confirm grouping and time boundaries behave as intended. |
| Data and context | Check delayed, missing or duplicate records. Verify added context does not erase matches or multiply counts. |
| Retest after tuning | Repeat positive and negative tests after any filter, threshold or query change. Preserve the results. |

### Assess noise without hiding uncertainty

Report reviewed true positives, false positives, authorized simulations and unresolved alerts separately. Give the review sample size. If reporting a false-positive percentage, state its numerator and denominator. A correct alert on an authorized simulation is not automatically a false positive; label authorization separately.

The inherited workload target is 3 to 5 alerts per rule per day, with 1 to 10 used in the local review. Above 10 requires tuning and another observation period. This is a queue-capacity control, not proof of detection quality. Do not weaken coverage or manufacture alerts to meet a quota. Zero alerts require a fresh positive test and a documented review decision.

> [!IMPORTANT]
> Record the runnable logic, data source, false-positive assessment and verified ATT&CK mapping together. No threshold is approved from intuition alone.

---

## 05 / Configure and enrich

# Create the test rule

Use the local settings below. A test rule must stay outside the Jira case-creation route.

| Setting | Local requirement |
|---|---|
| Schedule and lookback | Run every 1 hour. Query the previous 1 hour. |
| Alert threshold | Greater than 0 results. Put the behavior threshold inside the query. |
| Event grouping | Group all query results into a single alert. |
| Suppression | Off. Duplicate handling is downstream and must be verified. |
| Incident creation | Enabled in Sentinel. Test incidents must not create Jira cases. |
| Incident alert grouping | Match Host only, within 5 hours. |
| Reopen closed match | Off. |
| Automated response | Leave empty. |
| Entities | Host is mandatory, using FullName. Add Account and IP only from valid single-value fields. Complete or remove every mapping row. |
| Custom details | Include every required output field. Use the column name as the key and map its value to that column. Repeat mapped identities here for readable ticket data. |

### Add useful context and check its limits

Link related records using a supported host, account, process or other identifier and an explicit time window. This correlation connects evidence from separate records. State what it establishes and what it cannot prove. Check for unrelated records joining together, duplicated counts and missing matches. Keep the original evidence available.

Verify counts, evidence lists, names and time values on an actual alert. Inspect ExtendedProperties, the stored alert details, to confirm the expected custom fields arrived. Check list truncation and absent values. A multi-host test must prove that the title, entities and ticket preserve every affected host. Single-alert grouping does not guarantee one Jira ticket per query row.

### Keep the routing boundary explicit

The source card states that Jira automation routes incident titles containing SOC-BUILD. Confirm that behavior in the current environment. Use SOC-TEST for both the rule name and alert title during testing. Verify that no Jira case is created. Do not place SOC-BUILD in a test title.

> [!IMPORTANT]
> The one-hour schedule and lookback are local requirements. Measure collection delay and time-boundary misses. If they prevent reliable coverage, document the gap and request a reviewed design change before release.

Store the full register record or its durable reference in the rule description, subject to the current guide. Keep the alert description to one short summary line. The ticket’s longer description comes from the custom details. Tag the single verified technique that this build covers.

---

## 06 / Observe and release

# Review the evidence before release

Prepare initial analyst guidance before release. Complete the nine-block playbook from real cases afterward.

### Observe for at least 48 hours

Run the unchanged SOC-TEST rule for the source card’s 48 to 62 hour observation period, with a minimum of 48 hours. Record start and end times. If you change the logic or settings, rerun the tests and restart observation. Keep test incidents outside Jira.

| Review item | Required evidence |
|---|---|
| Volume and quality | Daily alert count, reviewed outcomes and false-positive causes. Retune above 10 per day. Explain zero alerts and rerun the positive test. |
| Alert contents | Custom details present in ExtendedProperties. Host mapping populated. Valid Account and IP mappings where available. |
| Title and identity | Readable short host and count with units. Verify different subjects remain distinguishable; use alert IDs to identify repeat alerts. |
| Ready for an analyst | Initial checks, evidence links, authority limits and escalation contact available. No unresolved critical review questions. |
| Independent query review | A second analyst reruns the query and positive/negative tests. Record reviewer, date, findings and fixes. |
| Register complete | Baseline, threshold, test results, observation results, mapping, known limits and outstanding requests linked. |

### Use the exact naming pattern

```text
Test rule:  SOC-TEST-<TECHNIQUE>-<SCOPE>-<TID>
Live rule:  SOC-BUILD-<TECHNIQUE>-<SCOPE>-<TID>
Test title: SOC-TEST-<TECHNIQUE> - {{ShortHost}} - {{PrimaryCount}} <unit>
Live title: SOC-BUILD-<TECHNIQUE> - {{ShortHost}} - {{PrimaryCount}} <unit>
Playbook:   PB-<Detection ID>
File:       PB-<Detection ID>-v1
```

Detection ID omits SOC-BUILD-. Replace PrimaryCount with your count column. IDs and filenames use hyphens, no spaces or underscores. Do not add DRAFT, TEMP or personal names.

### Release through the named authority

The Operations Lead reviews the register and observation record. Record the named release authority for this cycle and the approval date. Only that authority changes both SOC-TEST prefixes to SOC-BUILD. Confirm the current assignment.

Verify the first live alert reaches Jira once with the expected evidence. Keep the previous version and a documented way to disable or revert the rule. Record the release time, approver and version. If routing or coverage fails, notify the owner and use the agreed rollback procedure.

---

## 07 / Work a case

# Write the analyst playbook

Work at least one real Alert Case from your detection, start to finish. Use that experience to complete the guide.

An Alert Case is the initial Jira triage record. A Security Case is the investigation record created when case-promotion criteria are met. Rule release, case promotion and escalation to a more senior analyst are separate decisions. Use these terms consistently.

Copy PB-TEMPLATE-Analyst-Playbook-v2 and use Guide 02 §04 for the block requirements and §07 for the worked example. Keep all nine blocks. If one does not apply, retain it and explain why in one sentence. Date observed results and distinguish them from anticipated behavior.

| Block | Required content |
|---|---|
| 1. Header | Playbook ID, detection, verified ATT&CK technique, client tier, author, version, status and dates. |
| 2. Trigger | Two or three plain sentences: behavior, table, concrete threshold and the evidence that separates it from normal activity. |
| 3. Scope and authority | Named assets, client and tier. State what the SOC is authorized to do and how handling differs by tier. |
| 4. First-minute checks | Three to five ordered questions, each with a decision. All must be answerable from the Alert Case description alone. Mark the deciding check. |
| 5. Verification queries | Usually two tested KQL queries: one checks the central question; one checks whether the action succeeded. Include observed result, test date and visibility limits. |
| 6. Case outcome | Map observed patterns to the seven Charter dispositions, meaning case-outcome labels. Provide a model triage note for applicable outcomes. |
| 7. Promote or escalate | State separately when to create a Security Case and when Tier 2 review is needed. Include criterion 5: the analyst cannot reach a confident disposition. |
| 8. Security Case | Describe the investigation record created on promotion. Identify each required field and who sets it. |
| 9. False positives and gaps | Named legitimate accounts, scanners, maintenance, missing visibility and linked infrastructure requests. Date every entry. |

### Route uncertainty and authorized tests correctly

Consider all seven Charter outcomes. Explicitly include Authorized Simulated Activity and Insufficient Evidence. Confirm simulation authorization from a reliable record; resemblance alone is insufficient. Exclude authorized simulations from threat metrics according to the Charter. Insufficient Evidence requires an Infrastructure & Visibility Request.

> [!IMPORTANT]
> Tier 1 may close Alert Cases. Tier 1 does not archive Security Cases, approve recommendations or perform remediation. Do not write a playbook step that grants authority the analyst does not hold.

---

## 08 / Review and maintain

# Make the work usable on shift

Publication requires independent use. Maintenance keeps the detection tied to current behavior and current data.

### Test the playbook with another analyst

Time your first-minute checks against a real Alert Case. Reach a defensible disposition in under 60 seconds using the case description and playbook. Move investigation work out of that first-minute section. Then have a second analyst work a different Alert Case using the playbook alone. Record elapsed time, outcome and every question they had to ask. Incorporate the answers and retest unclear steps.

| Review | Required decision or record |
|---|---|
| Second analyst | Different case completed without author coaching. Questions and fixes recorded. |
| Process & Documentation | All nine blocks, correct IDs and filenames, Charter terminology and Guide 02 submission checklist checked. |
| Operations Lead | Analytical review, authority boundaries and final publication approval. |
| Master Document Index | Approved playbook linked. Detection Register and rule references updated. |

Before submission, verify every published query was tested in the range with its result and date recorded. Check Guide 02 §06 for environment facts and §09 for the full checklist. Ensure every step can be completed today with the supported tools. A missing capability belongs in the limitations record, not in an invented instruction.

### Assign maintenance before closing the build

Record a named owner, next review date, alert-volume limit, data-freshness limit and response when either limit is crossed. Review after the first live case and on the recorded schedule. Trigger an earlier review after a missed detection, recurring false positive, changed data fields, asset change or new attacker variation.

Track alerts per day, reviewed outcomes, duplicate tickets, missing custom details and failed or delayed data collection. Separate unresolved cases from false positives. Zero alerts should trigger a data-health and test check when activity was expected. A quiet rule can be healthy or blind; establish which with evidence.

Version every logic, threshold, exclusion and playbook change. Record the reason and expected coverage effect. Repeat positive and negative tests, obtain the required review, and use SOC-TEST observation before another release when detection behavior or settings change. Retire obsolete rules deliberately and update the index.

> [!NOTE]
> Completion record: Detection version ______ Playbook version ______<br>
> Independent reviewer ______ Operations approval/date ______<br>
> Published index link ______ Owner ______ Next review ______

A completed build has reproducible evidence, passing tests, documented limitations, reviewed routing and an independently tested playbook. A documented visibility gap is also a valid outcome. It does not become an approved detection until the missing evidence can be tested.

---

## 09 / References and local checks

# Keep the source of truth visible

Local requirements are preserved from the supplied v2 card. Recheck environment facts before using them.

| Reported environment fact | Check and consequence |
|---|---|
| Event 4625 is not collected | Confirm the current table and window. The source card directs failed-logon work to DeviceLogonEvents. |
| Windows logs are sparse | Confirm Security and System log coverage. Missing records can prevent corroboration. |
| Defender Device* tables are primary | Confirm onboarding, required fields and current data arrival for each scoped host. |
| Security tools create routine noise | Validate named Defender processes and scanner accounts before applying reviewed exclusions. |
| One shared virtual network | An internal IP address does not establish that activity is benign. |
| Participant machines are temporary | Use named always-on assets or honeypots for persistent rule scope. |

### Local document set

Use the existing documents under their current file names, even where they retain Fusion SOC branding. The supplied card links the Charter, Alert Intake and Promotion Standard, Detection Authoring Guide, Playbook Authoring Guide, template and trackers. Their full contents were not part of this redesign review. Resolve a conflict with the Operations Lead and the authoritative guide before release.

| Reference | Use |
|---|---|
| Charter / OS-01 | Case outcomes, case promotion, closure and authority. |
| Guide 01 | Query construction, rule settings, baseline and observation. |
| Guide 02 / Template v2 | Nine playbook blocks, environment facts and submission checks. |
| Sign-up tracker / Detection Register | Claim ownership and retain the complete build evidence. |

*These are internal Pacific Watch documents and are not published here.*

### Method and technical references

The lifecycle draws on Huntress’s published lab-to-log detection method: study behavior, reproduce it, inspect actual records, write against those records, validate, tune and add context. The review, Jira, playbook and maintenance controls here are Pacific Watch requirements or additions to this card. This is not a claim about a named internal Huntress framework.

- [Huntress: The OID Problem, detection development method](https://www.huntress.com/blog/ldap-active-directory-detection-part-one)
- [MITRE ATT&CK: verify technique IDs and mechanisms](https://attack.mitre.org/)
- [Microsoft: Kusto string operators](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators)
- [Microsoft: Scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)

Editorial sources: SOC-Detection-Build-Card-v2.pdf.pdf; hunt-report-writing-style.md; pacific-watch-identity (1).html. Revised 25 September 2026. The card is an operating template, not evidence that any detection has passed testing.

---

## Conversion notes

- **Naming pattern block:** in the PDF, the two title lines wrap onto a second line because of page width. They are joined onto one line here.
- **Fill-in boxes:** the working record (section 01) and completion record (section 08) are shown as note callouts with the blanks kept.
- **Highlighted boxes:** the PDF's highlighted boxes are shown as GitHub callouts. The wording is unchanged.
- **Internal links:** in the PDF, the reference names in section 09 link to internal documents. Those links are removed here and in the published PDF.
- **Page furniture:** the running header ("Detection engineering / v3.0") and footer ("Pacific Watch / SOC operating guide, 01 / 09") are not repeated on every section.
