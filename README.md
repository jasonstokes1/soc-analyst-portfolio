# SOC Analyst Investigations: LOGN Pacific Internship

**Alert-to-verdict investigations from my Cybersecurity Analyst internship at LOGN Pacific**: real alerts in a shared Azure environment, worked end to end with Microsoft Sentinel, Microsoft Defender for Endpoint, and KQL.

`Microsoft Sentinel` · `Microsoft Defender for Endpoint` · `KQL` · `Incident Response` · `MITRE ATT&CK`

---

## Investigations

| | Investigation | Platform | Verdict | MITRE ATT&CK |
|---|---|---|---|---|
| 🔐 | **[Password Spraying from a Public IP](01-password-spraying.md)**: caught by a rule I built; a re-check found a later compromise my rules missed, so I built a new rule to close the gap | Windows | True Positive | T1110.003 |
| 💣 | **[Ransomware Attack Chain + Device Isolation](02-ransomware-simulation.md)** | Windows | Benign Positive (simulation); critical in production | T1053 · T1059.001 · T1105 · T1486 |
| 🐧 | **[Tool Download on a Linux Server](03-linux-tool-download.md)** | Linux | Benign Positive (scheduled test) | T1105 |

---

## Skills demonstrated

**Detection engineering** (3 custom Sentinel analytics rules, including one built to close a gap I found) · **incident triage and classification** · **KQL threat hunting** · **process-tree and parent-process analysis** · **time correlation** · **containment** (Defender device isolation) · **Windows and Linux telemetry** · **MITRE ATT&CK mapping**.

<sub>Cyber-range exercises; no real victims. Screenshots redacted.</sub>
