# Indicators of Compromise
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Usage Notes

This IOC list was derived exclusively from confirmed telemetry collected during the investigation of INC-2026-03-01. Every indicator references the specific evidence event that produced it.

> **Confidence ratings reflect evidentiary support, not threat severity.**
> A LOW confidence IOC is not less dangerous — it means less evidence is available to confirm it.

These indicators should be used for:
- Threat hunting across the broader environment
- SIEM alert rule tuning
- Firewall and endpoint blocklist updates
- Credential rotation prioritization

---

## Hosts

| Indicator | Type | Role | Confidence | Source Event |
|---|---|---|---|---|
| `WKSTN-MKT-04` | Hostname | Attack origin — plant engineering workstation | HIGH | Evidence 1, 3, 4, 5 |
| `SRV-APP-INT` | Hostname | Primary target — HR application server | HIGH | Evidence 1, 2 |
| `10.0.50.99` | IPv4 | Secondary target — identity unknown | MEDIUM | Evidence 4, 5 |

---

## IP Addresses

| Indicator | Type | Direction | Confidence | Source Event |
|---|---|---|---|---|
| `192.168.15.44` | IPv4 | Source — WKSTN-MKT-04 | HIGH | Evidence 1, 2, 3, 4, 5 |
| `10.0.50.88` | IPv4 | Destination — SRV-APP-INT | HIGH | Evidence 2 |
| `10.0.50.99` | IPv4 | Destination — unknown host | MEDIUM | Evidence 4, 5 |

---

## User Accounts

| Indicator | Type | Context | Confidence | Source Event |
|---|---|---|---|---|
| `m.perez` | Username | Authenticated session user on WKSTN-MKT-04 — confirmed attack origin | HIGH | Evidence 1, 3 |
| `admin` | Username | Administrative account used in PsExec `-u` argument — credential confirmed compromised | HIGH | Evidence 1 |

> **Action required:** The `admin` account credential must be treated as compromised and rotated immediately. All active sessions authenticated as `admin` across the domain should be terminated and reviewed. The full access scope of this account across domain systems is unknown without Domain Controller data.

---

## Processes

| Indicator | Type | Path | Behavior | Confidence | Source Event |
|---|---|---|---|---|---|
| `psexec.exe` | Process name | `C:\Windows\System32\psexec.exe` | Remote execution attempt against SRV-APP-INT with plaintext credentials | HIGH | Evidence 1 |
| `wmic.exe` | Process name | `C:\Windows\System32\wbem\WMIC.exe` | Local account enumeration (`useraccount get name,sid`) | HIGH | Evidence 3 |
| `cmd.exe` | Process name | System path (standard) | Parent process for both psexec.exe and wmic.exe — active interactive session | HIGH | Evidence 1, 3 |

---

## Command Lines

| Indicator | Type | Confidence | Source Event |
|---|---|---|---|
| `psexec.exe \\SRV-APP-INT -u admin -p [REDACTED] cmd.exe` | Full command line | HIGH | Evidence 1 |
| `WMIC.exe useraccount get name,sid` | Full command line | HIGH | Evidence 3 |

> **Note on credential redaction:** The plaintext password passed via `-p` in the PsExec command is redacted in this document. The raw value was captured in Sysmon logs and is available in the Elastic SIEM investigation record under INC-2026-03-01. It should be treated as a confirmed compromised credential and not reproduced in documentation outside secure channels.

---

## Network Indicators

| Indicator | Type | Protocol | Port | Action | Confidence | Source Event |
|---|---|---|---|---|---|---|
| `192.168.15.44 → 10.0.50.88` | Network flow | SMB (PsExec) | 445 | Attempted | HIGH | Evidence 1, 2 |
| `192.168.15.44 → 10.0.50.99` | Network flow | RDP | 3389 | Permitted (outcome unknown) | HIGH | Evidence 4 |
| `192.168.15.44 → 10.0.50.99` | Network flow | SMB | 445 | Blocked | HIGH | Evidence 5 |

---

## Ports and Protocols

| Port | Protocol | Observed Use | Firewall Outcome |
|---|---|---|---|
| 445 | SMB | PsExec service installation attempt on SRV-APP-INT; direct SMB to 10.0.50.99 | Not blocked for SRV-APP-INT / Blocked for 10.0.50.99 |
| 3389 | RDP | Remote desktop attempt to 10.0.50.99 | Permitted |

---

## Log Sources and Event IDs

| Event ID | Source | Observed In | Significance |
|---|---|---|---|
| Sysmon ID 1 | Microsoft-Windows-Sysmon | WKSTN-MKT-04 | Process creation with full command-line arguments — primary LotL detection source |
| 4688 | Microsoft-Windows-Security-Auditing | WKSTN-MKT-04 | Process creation (Security log) — corroborates Sysmon ID 1 |
| 4625 | Microsoft-Windows-Security-Auditing | SRV-APP-INT | Network logon failure — confirms authentication attempt reached target |
| Firewall ALLOW | Windows Defender Firewall | WKSTN-MKT-04 | Outbound RDP to 10.0.50.99 permitted |
| Firewall DROP | Windows Defender Firewall | WKSTN-MKT-04 | Outbound SMB to 10.0.50.99 blocked |

---

## Out-of-Scope Indicators (Flagged for Separate Investigation)

The following were observed during log review but are not attributed to INC-2026-03-01. They are included here for handoff to a follow-on investigation.

| Indicator | Type | Host | Concern |
|---|---|---|---|
| `chrome.exe` executing as `SYSTEM` from `C:\Windows\System32\` | Process anomaly | SRV-DC-01 | Anomalous binary path and privilege level on a Domain Controller |
| Administrative account → external API | Authentication + network | IT workstation (unspecified) | Potential unauthorized external communication |
| RDP between unverified segments | Network flow | Multiple (unspecified) | Possible lateral movement outside incident scope |

---

## Hunting Queries (Elastic / KQL)

The following queries can be used to search for related activity across the broader environment.

**PsExec execution by non-administrative users:**
```kql
event.code: "1" AND process.name: "psexec.exe" AND NOT user.name: ("Administrator" OR "svcadmin")
```

**WMIC account enumeration:**
```kql
event.code: "1" AND process.name: "wmic.exe" AND process.command_line: *useraccount*
```

**Outbound RDP from non-IT workstations:**
```kql
event.action: "Firewall ALLOW rule triggered" AND destination.port: "3389" AND NOT host.name: ("IT-*" OR "ADMIN-*")
```

**Plaintext credential patterns in command lines:**
```kql
event.code: "1" AND process.command_line: (* -p * OR * /p *)
```

**Combined RDP + SMB to same destination within 60 seconds:**
```kql
event.provider: "Windows Defender Firewall" AND destination.ip: "10.0.50.99" AND (destination.port: "3389" OR destination.port: "445")
```

---

## Related Documents

- [← Risk Assessment](../investigation/05-risk-assessment.md)
- [Evidence Analysis →](../investigation/03-evidence-analysis.md)
- [Detection Opportunities →](../detections/detection-opportunities.md)
- [Recommendations →](../remediation/recommendations.md)
