# Incident Overview
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Organization Profile

NorthBridge Manufacturing is a multinational producer of industrial automation components serving the automotive and energy sectors. The organization operates multiple production facilities connected to a centralized corporate network, with approximately 2,800 employees across its locations.

Business-critical services — Human Resources, Finance, Engineering, and Manufacturing — depend on Active Directory authentication and Windows-based infrastructure. Access to internal systems is controlled through network segmentation and role-based access policies, given the sensitivity of employee data, intellectual property, and operational technology (OT) documentation managed by the organization.

---

## Security Environment

| Component | Detail |
|---|---|
| **SOC** | 24/7 Security Operations Center |
| **SIEM** | Elastic SIEM |
| **Endpoint Telemetry** | Sysmon, Windows Defender Firewall, Endpoint Process Metadata |
| **Authentication Logs** | Windows Security Event Logs, Active Directory |
| **Infrastructure** | Hybrid On-Premises Active Directory + Windows Server |

The SOC monitors for the following threat categories:

- Credential misuse
- Lateral movement
- Privilege abuse
- Living-off-the-Land (LotL) techniques
- Unauthorized remote administration
- Internal reconnaissance

---

## Incident Description

During routine overnight monitoring, the SOC identified anomalous authentication activity targeting an internal Human Resources application server.

The initial alert was classified at **low / informational severity**. However, analyst review revealed that the originating workstation belonged to a **plant engineering user** — an account with no authorization to perform administrative operations against internal servers.

Shortly after the authentication event, endpoint telemetry recorded:

- Execution of native Windows administrative utilities
- Outbound network connections on SMB (445) and Remote Desktop Protocol (3389)

No malware was detected. No exploit activity was observed. No endpoint protection alerts fired.

The investigation was opened to determine whether the behavior represented legitimate administrative activity or an early-stage intrusion leveraging Living-off-the-Land techniques.

---

## Investigation Objectives

1. Reconstruct the complete sequence of events using available telemetry.
2. Determine whether the authentication activity originated from authorized administrative action.
3. Identify evidence of internal reconnaissance.
4. Assess whether the observed behavior is consistent with attempted lateral movement.
5. Evaluate the potential business impact to Human Resources infrastructure.
6. Recommend containment measures and detection improvements based solely on confirmed evidence.

---

## Available Telemetry

| Source | Coverage |
|---|---|
| Windows Security Event Logs | Authentication events, logon failures, process creation |
| Sysmon Process Creation (Event ID 1) | Command-line arguments, parent-child process relationships |
| Windows Defender Firewall Logs | Allowed and blocked outbound connections |
| Active Directory Authentication Logs | Domain logon activity |
| Endpoint Process Metadata | Process names, paths, execution context |

---

## Evidence Not Available

The following evidence sources were **not accessible** during this investigation. All conclusions are scoped accordingly.

| Missing Source | Investigative Impact |
|---|---|
| Memory acquisition | Volatile artifacts, injected code, and runtime credentials cannot be confirmed |
| Disk forensic images | Persistence mechanisms, deleted files, and prefetch data are unknown |
| Network packet captures (PCAP) | Session content and data exfiltration cannot be assessed |
| EDR live response | Real-time process state and file system activity are unavailable |
| PowerShell transcription logs | Any PowerShell-based activity outside Sysmon coverage is unknown |
| Domain Controller replication data | Kerberos ticket activity and potential DCSync operations cannot be evaluated |

---

## Evidence Classification Standard

All findings in this investigation are explicitly classified using the following scale:

| Classification | Definition |
|---|---|
| **CONFIRMED** | Directly supported by log evidence with specific Event IDs and timestamps |
| **INFERRED** | Logically consistent with available evidence but not directly observable |
| **UNKNOWN** | Cannot be determined from available telemetry — additional evidence required |

No conclusion in this investigation exceeds what the available evidence supports.

---

## Related Documents

- [Timeline →](02-timeline.md)
- [Evidence Analysis →](03-evidence-analysis.md)
- [Attack Hypothesis →](04-attack-hypothesis.md)
- [Risk Assessment →](05-risk-assessment.md)
