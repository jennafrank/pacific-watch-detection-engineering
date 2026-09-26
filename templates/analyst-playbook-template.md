# PB-&lt;Detection ID&gt;: &lt;short name&gt;

> Card reference: section 07, "Write the analyst playbook." Keep all nine blocks. If one does not apply, retain it and explain why in one sentence. Date observed results and distinguish them from anticipated behavior. Do not write a step that grants authority the analyst does not hold.

## Block 1. Header

*Required: playbook ID, detection, verified ATT&CK technique, client tier, author, version, status and dates.*

| Field | Value |
|---|---|
| Playbook ID | PB-&lt;Detection ID&gt; |
| Detection | |
| ATT&CK technique (verified) | |
| Client tier | |
| Author | |
| Version / status | |
| Dates | |

## Block 2. Trigger

*Required: two or three plain sentences: behavior, table, concrete threshold and the evidence that separates it from normal activity.*

## Block 3. Scope and authority

*Required: named assets, client and tier. State what the SOC is authorized to do and how handling differs by tier.*

## Block 4. First-minute checks

*Required: three to five ordered questions, each with a decision. All must be answerable from the Alert Case description alone. Mark the deciding check.*

| # | Check | Decision |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |

## Block 5. Verification queries

*Required: usually two tested KQL queries: one checks the central question; one checks whether the action succeeded. Include observed result, test date and visibility limits.*

**Query A: central question.** Tested YYYY-MM-DD; observed result:

```kql
```

**Query B: did the action succeed?** Tested YYYY-MM-DD; observed result:

```kql
```

**Visibility limits:**

## Block 6. Case outcome

*Required: map observed patterns to the seven Charter dispositions. Provide a model triage note for applicable outcomes. Consider all seven, including Authorized Simulated Activity and Insufficient Evidence.*

| Observed | Disposition | Model triage note |
|---|---|---|
| | True Positive – Malicious | |
| | Authorized Participant Activity | |
| | Authorized Simulated Activity | Confirm authorization from a reliable record; resemblance alone is insufficient. |
| | False Positive | |
| | Benign Positive | |
| | Insufficient Evidence | Requires an Infrastructure & Visibility Request. |
| | Duplicate | |

## Block 7. Promote or escalate

*Required: state separately when to create a Security Case and when Tier 2 review is needed. Include criterion 5: the analyst cannot reach a confident disposition.*

**Promote (create a Security Case) when:**

**Escalate (Tier 2 review) when:**

## Block 8. Security Case

*Required: describe the investigation record created on promotion. Identify each required field and who sets it.*

| Field | Value on promotion | Set by |
|---|---|---|
| | | |

## Block 9. False positives and gaps

*Required: named legitimate accounts, scanners, maintenance, missing visibility and linked infrastructure requests. Date every entry.*

- (YYYY-MM-DD)
