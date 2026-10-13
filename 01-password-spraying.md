# Detection & Investigation: Password Spraying from a Public IP

**SOC investigation of an internet password-guessing campaign, caught by a Microsoft Sentinel analytics rule I built**: scoped with KQL across 7 days of logon telemetry, confirmed no account was compromised, and classified as a True Positive.

`Microsoft Sentinel` · `Microsoft Defender for Endpoint` · `KQL` · `Detection Engineering` · `MITRE ATT&CK`

---

## What happened

A public IP, **80.66.83.43**, made about **520 failed login attempts across 11 devices** in 7 days, targeting only the generic accounts `admin` and `administrator`. My detection rule raised an incident, and the investigation confirmed **no successful logins**.

| Investigation question | Finding | Evidence |
|---|---|---|
| Is this a real attack? | **Yes**: automated password guessing from the internet | ~520 `LogonFailed` events from one public IP |
| How wide was it? | **11 devices** targeted | `dcount(DeviceName)` over 7 days |
| Which accounts? | Only `admin` and `administrator` | `make_set(AccountName)` |
| Did anyone get in? | **No** | 0 `LogonSuccess` events from the IP |
| Is it linked to another compromise? | **No**: a "similar" incident only shared this IP as an entity | Reviewed the related incident's alert sources |

**Verdict:** True Positive (suspicious activity), no compromise. **Recommendation:** block the IP, keep RDP/SSH off the internet, enforce lockout and MFA.

---

## Skills demonstrated

**Detection engineering** (custom Sentinel analytics rule: thresholds, entity mapping, alert grouping) · **incident triage** · **KQL pivoting** (`summarize`, `dcount`, `make_set`, `countif`) · **scoping across devices and time** · **verifying correlated incidents** rather than assuming · **MITRE ATT&CK mapping** (T1110.003).

---

## 1. Detection: the rule I built

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIPType == "Public"
| summarize FailedAttempts = count(),
            ComputersTargeted = dcount(DeviceName),
            Computers = make_set(DeviceName)
    by RemoteIP
| where FailedAttempts >= 50
```

| Setting | Value | Why |
|---|---|---|
| Severity | Medium | Failed guessing alone is not a breach |
| Frequency | Every hour | Fast enough to catch active campaigns |
| Alert grouping | By IP, 24 hours | One incident per attacker instead of dozens |
| Entities | IP | Lets Sentinel link related incidents |

![Detection rule](screenshots/01-rule.png)

I also built a companion **High** rule that fires only when failures are **followed by a success** from the same IP (`Failed >= 5 and Success >= 1`), so a guess that works is escalated immediately.

## 2. Triage

Claimed the incident, reviewed severity and entities, and set status to Active.

![Incident](screenshots/01-incident.png)

## 3. Scoping: 7 days of activity from the IP

```kql
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where RemoteIP == "80.66.83.43"
| summarize Attempts = count(),
            Devices = dcount(DeviceName),
            Accounts = make_set(AccountName)
    by ActionType
```

![Query results](screenshots/01-query-results.png)

## 4. Related-incident check

Sentinel listed a "similar" incident on another device. Its alerts came from a different source and the IP appeared only as a shared entity, so I did not link the two. **Similar means a shared entity, not the same attack.**

---

## MITRE ATT&CK

| Tactic | Technique | Observed |
|---|---|---|
| Credential Access | T1110.003 Password Spraying | Common admin usernames tried across 11 devices |

## Lessons learned

- **Spraying vs. brute force:** many accounts with few tries each slips under lockout thresholds; one account with many tries triggers them.
- **Pair every "failed" rule with a "failed then succeeded" rule.** The second one is what catches the guess that works.

<sub>Cyber-range exercise during my Cybersecurity Analyst internship at LOGN Pacific. Live internet traffic against lab VMs; no real victim.</sub>
