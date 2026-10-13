# SOC Analyst Portfolio

Investigations from my **Cybersecurity Analyst internship at LOGN Pacific**: remote work on real alerts in a shared Azure environment using **Microsoft Sentinel, Microsoft Defender for Endpoint, and Tenable**. Some activity is live internet attack traffic and some comes from attack simulations.

## Featured investigations

| # | Investigation | Platform | Verdict | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | [Password spraying from a public IP](01-password-spraying.md) | Windows | True Positive, no compromise | T1110.003 |
| 2 | [Ransomware attack-chain simulation + device isolation](02-ransomware-simulation.md) | Windows | Benign Positive (simulation); critical in production | T1053, T1059.001, T1105, T1486 |
| 3 | [Tool download on a Linux server](03-linux-tool-download.md) | Linux | Benign Positive (scheduled test) | T1105 |

## Other work during the internship

- Built and tuned **2 Sentinel analytics rules** (brute force; successful brute force) with entity mapping and alert grouping
- Ran authenticated **Tenable** scans and remediated **3 High** vulnerabilities to 0, verified by rescan
- Practiced **containment**: isolated and released a device in Defender, verified through Action center
- Threat hunts on Linux (download → chmod → execute chain) and a **data-source review** that identified logging blind spots
- Investigated 6 incidents end to end, including persistence (registry Run key), service tampering, and data archiving (T1560) alerts

## Skills

KQL · Microsoft Sentinel · Microsoft Defender for Endpoint · Tenable Vulnerability Management · Azure · Windows and Linux log analysis · MITRE ATT&CK · NIST incident response
