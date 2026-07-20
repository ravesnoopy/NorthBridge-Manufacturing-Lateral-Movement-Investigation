# Remediation Recommendations
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Framework Reference

This remediation plan follows the **NIST SP 800-61 Rev. 2** incident response lifecycle:

- **Containment** — Stop the immediate threat
- **Eradication** — Remove the attacker's access and artifacts
- **Recovery** — Restore normal operations securely
- **Post-Incident Activity** — Prevent recurrence

All recommendations are tied directly to confirmed or inferred evidence from INC-2026-03-01. No recommendation is generic — each addresses a specific gap exposed by this incident.

---

## Phase 1 — Immediate Containment

*Actions to be taken within the first 4 hours of incident confirmation.*

---

### CON-01 — Isolate WKSTN-MKT-04

**Priority:** Critical
**Evidence basis:** All five observed attack events originated from this host

Isolate `WKSTN-MKT-04` (192.168.15.44) from the network at the switch port or via endpoint policy. Preserve the host in its current state — do not reimage before forensic triage is completed.

If EDR is available, initiate a live response session to collect:
- Running processes and open network connections
- Recently modified files and prefetch artifacts
- Browser history and recently accessed files under `m.perez`'s profile
- Any PsExec-related artifacts (`PSEXESVC` installation, temp files)

---

### CON-02 — Disable and Rotate the `admin` Account Credential

**Priority:** Critical
**Evidence basis:** Plaintext credential confirmed captured in Sysmon logs (Evidence 1, T1552.001)

The `admin` account credential is a confirmed indicator of compromise. It was recorded in Sysmon Event ID 1 and ingested into the Elastic SIEM pipeline.

Required actions:
1. Disable the `admin` account immediately pending investigation
2. Rotate the credential on all systems where it is valid
3. Audit all authentication events for the `admin` account across the domain for the 30 days prior to this incident
4. Identify and terminate any active sessions authenticated as `admin`

The full blast radius of this credential cannot be determined without Domain Controller authentication logs.

---

### CON-03 — Suspend `m.perez` Account Pending Investigation

**Priority:** High
**Evidence basis:** Account used as attack origin — insider threat cannot be excluded

Suspend the `m.perez` Active Directory account and invalidate active Kerberos tickets (klist purge or account disable/re-enable cycle). Do not permanently disable until investigation determines whether the account was compromised externally or used by the account holder.

Notify HR and legal as appropriate given the insider threat possibility.

---

### CON-04 — Block Outbound RDP from Non-Administrative Workstations

**Priority:** High
**Evidence basis:** Outbound RDP from WKSTN-MKT-04 to 10.0.50.99 was permitted (Evidence 4)

Implement a Group Policy or firewall rule to block outbound connections on port 3389 from workstations not in the approved IT/administrative asset group. This control would have contained the lateral movement attempt at the network layer.

---

### CON-05 — Identify and Investigate 10.0.50.99

**Priority:** High
**Evidence basis:** Destination of permitted RDP and blocked SMB attempts — identity unknown

Query the CMDB, DHCP logs, and Active Directory computer objects to identify the host at `10.0.50.99`. Until identified:
- Review all inbound connections to this IP for the 24 hours surrounding the incident
- Treat it as potentially compromised given the permitted RDP connection

---

## Phase 2 — Eradication

*Actions to be completed within 24–72 hours.*

---

### ERA-01 — Audit PsExec Deployment Across the Environment

**Priority:** High
**Evidence basis:** PsExec present on a plant engineering workstation with no legitimate use case

PsExec is not a default Windows binary — it requires deliberate installation. Its presence on `WKSTN-MKT-04` is itself anomalous. Query the environment for `psexec.exe` across all endpoints and remove it from any host where no administrative authorization exists.

```kql
event.code: "1" AND process.name: "psexec.exe"
```

Run this query across the full 90-day log retention window to identify any prior undiscovered usage.

---

### ERA-02 — Review `admin` Account Access Scope

**Priority:** Critical
**Evidence basis:** Administrative credential compromised — scope unknown without DC data

Enumerate all systems, shares, and services where the `admin` account holds permissions. Assess whether any unauthorized access or changes occurred in the window between the credential's compromise and its rotation.

This review requires Domain Controller replication data and is currently constrained by the available telemetry documented in the investigation scope.

---

### ERA-03 — Search for PSEXESVC Artifacts on SRV-APP-INT

**Priority:** Medium
**Evidence basis:** PsExec authentication failed (Evidence 2) — but additional attempts outside the log window cannot be excluded

On `SRV-APP-INT`, check for:
- Presence of `PSEXESVC.exe` in `C:\Windows\` or `C:\Windows\System32\`
- Windows Service entries for PSEXESVC
- Event ID 7045 (new service installed) in the System log around the incident timeframe

A positive finding would indicate that PsExec authentication succeeded on an unobserved attempt.

---

## Phase 3 — Recovery

*Actions to restore normal operations with verified security posture.*

---

### REC-01 — Re-enable `m.perez` Only After Investigation Conclusion

Return the `m.perez` account to active status only after the investigation determines whether the account was externally compromised or involved insider activity. If externally compromised, issue new credentials and enforce MFA enrollment before restoring access.

---

### REC-02 — Verify SRV-APP-INT Integrity Before Returning to Production

Before returning `SRV-APP-INT` to normal operation, verify:
- No unauthorized user accounts were created (review Event ID 4720)
- No scheduled tasks or services were added around the incident timeframe
- Application logs show no unauthorized data access during the incident window

---

### REC-03 — Validate 10.0.50.99 Before Returning to Service

If `10.0.50.99` is identified and was accessible via the permitted RDP connection, treat it as potentially compromised and apply the same integrity verification process as SRV-APP-INT before returning it to production.

---

## Phase 4 — Long-Term Hardening

*Strategic controls to prevent recurrence of this attack class.*

---

### HARD-01 — Deploy AppLocker or WDAC to Block Unauthorized Administrative Tools

**Addresses:** PsExec execution by non-administrative users (Gap 1)
**Technique mitigated:** T1021.002, T1569.002

Implement Windows Defender Application Control (WDAC) or AppLocker policies to block the execution of tools including `psexec.exe`, `psexec64.exe`, and similar remote administration utilities on workstations outside the approved IT asset group.

WDAC is preferred over AppLocker for modern Windows 10/11 and Windows Server 2016+ environments due to kernel-level enforcement.

---

### HARD-02 — Enforce MFA on All Privileged Accounts

**Addresses:** Administrative credential compromise enabling unauthorized access
**Technique mitigated:** T1552.001, T1021.002

A plaintext password as a command-line argument is only useful if the password alone is sufficient for authentication. MFA on privileged accounts — including the `admin` account — would have prevented the credential from being usable even after it was exposed in the Sysmon log.

Implement MFA via Windows Hello for Business, smart card authentication, or an approved third-party MFA provider for all accounts with administrative privileges across the domain.

---

### HARD-03 — Apply Principle of Least Privilege to User Accounts

**Addresses:** Plant engineering user with access to administrative credentials
**Technique mitigated:** T1021.002, T1087.001

`m.perez` — a plant engineering account — had sufficient access context to obtain and use an `admin` account credential. Review and restrict:
- Local administrator rights on workstations outside IT
- Access to credential stores, scripts, or documentation containing administrative passwords
- Group memberships that exceed the requirements of the plant engineering role

---

### HARD-04 — Enforce NTP Synchronization Across All Domain Hosts

**Addresses:** Timestamp discrepancy between WKSTN-MKT-04 and SRV-APP-INT degrading correlation confidence
**Reference:** Investigation limitation documented in 02-timeline.md

Configure all domain-joined hosts to synchronize time against a validated internal NTP hierarchy. Verify compliance via Group Policy and alert on hosts whose clock drift exceeds 5 minutes. Clock desynchronization is a detection dependency — uncorrelated timestamps degrade every time-based SIEM rule.

---

### HARD-05 — Implement Network Segmentation to Restrict Cross-Segment RDP and SMB

**Addresses:** Outbound RDP permitted from plant engineering segment to server segment
**Technique mitigated:** T1021.001, T1021

The plant engineering workstation segment (`192.168.15.0/24`) should not have default outbound access to the server segment (`10.0.50.0/24`) on ports 3389 or 445. Implement firewall rules at the network level — not only the host level — to enforce this segmentation.

---

## Pending Investigation Leads

The following items were identified during INC-2026-03-01 and require independent investigation. They are out of scope for this incident but should be prioritized given their potential severity.

| Lead | Host | Priority | Concern |
|---|---|---|---|
| `chrome.exe` executing as `SYSTEM` from `C:\Windows\System32\` | SRV-DC-01 | Critical | Anomalous process on a Domain Controller — potential compromise of domain authentication infrastructure |
| Administrative account accessing external APIs | IT workstation (unspecified) | High | Potential data exfiltration or unauthorized external communication |
| RDP connections between unverified network segments | Multiple | High | Possible additional lateral movement campaign beyond this incident scope |

> If the SRV-DC-01 finding is confirmed as malicious, the scope of remediation expands significantly — domain-wide credential rotation and a full Active Directory security review would be required.

---

## Remediation Tracking

| ID | Action | Phase | Priority | Status |
|---|---|---|---|---|
| CON-01 | Isolate WKSTN-MKT-04 | Containment | Critical | Open |
| CON-02 | Rotate `admin` credential | Containment | Critical | Open |
| CON-03 | Suspend `m.perez` account | Containment | High | Open |
| CON-04 | Block outbound RDP from non-admin workstations | Containment | High | Open |
| CON-05 | Identify 10.0.50.99 | Containment | High | Open |
| ERA-01 | Audit PsExec across environment | Eradication | High | Open |
| ERA-02 | Review `admin` account access scope | Eradication | Critical | Open |
| ERA-03 | Search for PSEXESVC on SRV-APP-INT | Eradication | Medium | Open |
| REC-01 | Re-enable `m.perez` post-investigation | Recovery | High | Pending investigation |
| REC-02 | Verify SRV-APP-INT integrity | Recovery | High | Open |
| REC-03 | Verify 10.0.50.99 integrity | Recovery | High | Pending identification |
| HARD-01 | Deploy AppLocker / WDAC | Hardening | High | Open |
| HARD-02 | Enforce MFA on privileged accounts | Hardening | Critical | Open |
| HARD-03 | Apply least privilege to user accounts | Hardening | High | Open |
| HARD-04 | Enforce NTP synchronization | Hardening | Medium | Open |
| HARD-05 | Network segmentation for RDP/SMB | Hardening | High | Open |

---

## Related Documents

- [← Risk Assessment](../investigation/05-risk-assessment.md)
- [← Detection Opportunities](../detections/detection-opportunities.md)
- [IOC List →](../iocs/ioc-list.md)
- [← Back to README](../README.md)
