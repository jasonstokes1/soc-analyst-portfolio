# Investigation 2: Ransomware Attack-Chain Simulation and Device Isolation

**Verdict:** Benign Positive (authorized attack simulation). In production this would be a **critical True Positive** requiring immediate isolation.
**Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, KQL
**MITRE ATT&CK:** T1053 Scheduled Task · T1059.001 PowerShell · T1105 Ingress Tool Transfer · T1486 Data Encrypted for Impact

## Summary

A Sentinel rule flagged PowerShell downloading scripts with `-ExecutionPolicy Bypass` on **windows-target-1**. I traced a scheduled job that downloads three scripts every 4 hours. One of them, `pwncrypt.ps1`, ran and encrypted 18 files. The source was the environment's own attack-simulation repository, so I classified it as an authorized simulation. I then practiced the containment step that a real case would require.

## Investigation

### 1. What ran, how often, and from where (3 days)

```kql
DeviceProcessEvents
| where DeviceName startswith "windows-target"
| where ProcessCommandLine contains "Invoke-WebRequest"
| project TimeGenerated, AccountName, ProcessCommandLine,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Findings:**

- **Process chain:** `powershell -File scriptNN.ps1` → `cmd.exe /c` → `powershell Invoke-WebRequest`, running as **SYSTEM**
- **Schedule:** every 4 hours, 12 minutes apart: `:12` pwncrypt.ps1, `:24` eicar.ps1, `:36` portscan.ps1
- **Saved to:** `C:\ProgramData`
- **Source:** the environment's attack-simulation repository on GitHub

### 2. Did the ransomware execute? (1 day)

```kql
DeviceFileEvents
| where DeviceName startswith "windows-target"
| where FileName contains "pwncrypt"
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated desc
```

**Finding:** yes. 18 files (CompanyFinancials, EmployeeRecords, ProjectList) were created on a user's Desktop and renamed with a `_pwncrypt` tag.

<!-- Screenshot: file events showing _pwncrypt files (blur usernames) -->

## Attack chain

| Step | What happened | MITRE |
|---|---|---|
| 1 | Scheduled job runs a PowerShell script | T1053 |
| 2 | PowerShell downloads tools from the internet | T1059.001, T1105 |
| 3 | Simulated ransomware encrypts files | T1486 |

## Containment practice

A real version of this case calls for isolating the device immediately. I practiced the full containment cycle in Defender on my own workstation VM:

| Step | Action | Verified by |
|---|---|---|
| Baseline | Connected through Azure Bastion | Connection worked |
| Contain | Defender → Isolate device (full isolation), with comment | Bastion: "target machine is currently unavailable" |
| Record | Action center logged the action | Comment, account and timestamp recorded |
| Release | Release from isolation, with comment | Bastion reconnected |

## What I learned

- Parent → child process chains show **how** something ran, not just what ran.
- A fixed schedule (every 4 hours at :12, :24, :36) points to automation.
- Context decides the verdict. The same evidence is benign in a simulation and critical in production, so I documented both.
