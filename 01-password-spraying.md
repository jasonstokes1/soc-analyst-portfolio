# Investigation 1: Password Spraying from a Public IP

**Verdict:** True Positive (suspicious activity), no compromise
**Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, KQL
**MITRE ATT&CK:** T1110.003 Brute Force: Password Spraying

## Summary

A Sentinel analytics rule I built fired on repeated failed logins from public IP **80.66.83.43**. I confirmed about 520 failed logins across 11 devices over 7 days, all targeting the generic accounts "admin" and "administrator", with **no successful logins**. I classified it as a True Positive with no compromise and recommended blocking the IP.

## Detection

I wrote this rule to catch password guessing from the internet:

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

<!-- Screenshot: the incident panel (blur tenant and subscription IDs) -->

## Investigation

1. **Triage:** claimed the incident, reviewed severity and entities (the IP).
2. **Scope:** pivoted to 7 days of logon activity from the IP:

```kql
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where RemoteIP == "80.66.83.43"
| summarize Attempts = count(),
            Devices = dcount(DeviceName),
            Accounts = make_set(AccountName)
    by ActionType
```

3. **Findings:**
   - About 520 `LogonFailed` events across 11 devices
   - Only "admin" and "administrator" attempted
   - **0** `LogonSuccess` events
4. **Related incident check:** a "similar" incident shared this IP only as an entity. Its alerts came from a different source, so this IP did not cause that compromise.

<!-- Screenshot: query results -->

## Conclusion

Automated password guessing from an internet IP against common admin account names. No account was compromised.

**Recommendations:**
- Block 80.66.83.43 at the network level
- Keep RDP and SSH off the public internet (use Azure Bastion or a VPN)
- Enforce account lockout and MFA

## What I learned

- Spraying and brute force look different in logs: many accounts with few tries each, versus one account with many tries.
- "Similar incident" in Sentinel means a shared entity, not the same attack. Always verify.
- A companion rule that looks for failures **followed by a success** catches the guesses that work. I built that rule next.
