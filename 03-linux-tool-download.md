# Investigation 3: Tool Download on a Linux Server

**Verdict:** Benign Positive (scheduled antivirus test)
**Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, KQL
**MITRE ATT&CK:** T1105 Ingress Tool Transfer (tactic: Command and Control)

## Summary

A Sentinel rule for **Ingress Tool Transfer** fired because `wget` on the Ubuntu server **linux-target-1** connected to external IP **89.238.73.97**. I found the download was the harmless **EICAR antivirus test file**, started by **Azure Run Command** on a fixed schedule, with nothing executed afterward.

## Investigation

### 1. First attempt: search the commands for the IP

```kql
DeviceProcessEvents
| where DeviceName startswith "linux-target-1"
| where ProcessCommandLine contains "89.238.73.97"
```

**No results.** That told me the command used a **domain name**, which DNS resolved to the IP, so the IP never appeared in the typed command.

### 2. Pivot to network events

```kql
DeviceNetworkEvents
| where DeviceName startswith "linux-target-1"
| where RemoteIP == "89.238.73.97"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessAccountName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
```

| Field | Value |
|---|---|
| RemoteUrl | secure.eicar.org |
| Port | 443 (HTTPS) |
| Account | root |
| Command | `wget https://secure.eicar.org/eicar.com.txt -O /tmp/eicar.txt` |

### 3. Who started it, and how often?

```kql
DeviceProcessEvents
| where DeviceName startswith "linux-target-1"
| where ProcessCommandLine contains "eicar"
| project TimeGenerated, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName
```

- **Parent:** `run-command-extension` (Azure Run Command, via the Azure VM agent), or `dash` (a shell it launches)
- **Schedule:** every run happened at **:24 past the hour** on multiple days, which points to automation, not a person

### 4. Did anything execute from /tmp afterward? (7 days)

```kql
DeviceProcessEvents
| where DeviceName startswith "linux-target"
| where FolderPath startswith "/tmp"
```

**No results.** Nothing ran from /tmp, and `eicar.txt` is a text file, not a program.

## Conclusion

An authorized, scheduled Defender test pushed through Azure Run Command. The rule worked correctly, but no malicious activity occurred.

## What I learned

- **Pivot when a search comes up empty.** The IP lived in network records, not in the command line.
- **Parent processes reveal the source.** Azure Run Command and an SSH login look very different (`sshd` → `bash` → `wget` would be an investigation).
- **Exact, repeating times mean automation.**
- **Hunt from several angles.** `FolderPath` catches programs run from /tmp however they were started; `ProcessCommandLine` catches scripts passed to a shell (`bash /tmp/x`).
