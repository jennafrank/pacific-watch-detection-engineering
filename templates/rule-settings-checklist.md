# Rule settings checklist

> Card reference: section 05, "Create the test rule." A test rule must stay outside the Jira case-creation route. Record the actual value next to each item.

| Done | Setting | Local requirement | Actual value |
|---|---|---|---|
| [ ] | Schedule and lookback | Run every 1 hour. Query the previous 1 hour. | |
| [ ] | Alert threshold | Greater than 0 results. Put the behavior threshold inside the query. | |
| [ ] | Event grouping | Group all query results into a single alert. | |
| [ ] | Suppression | Off. Duplicate handling is downstream and must be verified. | |
| [ ] | Incident creation | Enabled in Sentinel. Test incidents must not create Jira cases. | |
| [ ] | Incident alert grouping | Match Host only, within 5 hours. | |
| [ ] | Reopen closed match | Off. | |
| [ ] | Automated response | Leave empty. | |
| [ ] | Entities | Host is mandatory, using FullName. Add Account and IP only from valid single-value fields. Complete or remove every mapping row. | |
| [ ] | Custom details | Include every required output field. Use the column name as the key and map its value to that column. Repeat mapped identities here for readable ticket data. | |

## Routing and verification

- [ ] Rule name and alert title both use `SOC-TEST` during testing.
- [ ] No Jira case was created by a test incident.
- [ ] Custom details confirmed in ExtendedProperties on an actual alert.
- [ ] List truncation and absent values checked.
- [ ] Multi-host test: title, entities and ticket preserve every affected host.
- [ ] Collection delay and time-boundary misses measured for the one-hour window.
- [ ] Rule description holds the register record or its durable reference; alert description is one short summary line.
- [ ] The single verified technique is tagged.
