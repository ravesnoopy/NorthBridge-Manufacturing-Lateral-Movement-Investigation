# Risk Assessment
### INC-2026-03-01 | NorthBridge Manufacturing

---

## Assessment Scope

This risk assessment is based exclusively on evidence confirmed or inferred from INC-2026-03-01. It does not incorporate out-of-scope findings (chrome.exe on SRV-DC-01, external API access, inter-segment RDP) which require independent investigation before their business impact can be evaluated.

All risk ratings reflect the state of the environment **at the time of detection**, not after containment.

---

## Risk Rating Summary

| Risk Area | Likelihood | Impact | Overall Rating |
|---|---|---|---|
| Unauthorized access to HR application data | Medium | High | **HIGH** |
| Credential exposure via plaintext command-line argument | High | High | **CRITICAL** |
| Lateral movement to unidentified internal host (10.0.50.99) | Medium | Unknown | **MEDIUM–HIGH** |
| Internal account enumeration enabling follow-on attacks | High | Medium | **HIGH** |
| Detection gap — LotL techniques bypassing endpoint controls | High | High | **CRITICAL** |

---

## Risk 1 — Unauthorized Access to HR Application Infrastructure

**Rating: HIGH**
**Classification: INFERRED**

`SRV-APP-INT` is an internal Human Resources application server. The operator on `WKSTN-MKT-04` explicitly targeted this host using PsExec with administrative credentials. Authentication failed on the observed attempt, and no successful logon was confirmed in available telemetry.

However, the targeting of an HR server by a plant engineering account represents a policy violation regardless of outcome. If a subsequent unobserved authentication attempt succeeded — which cannot be excluded given the constraints of available telemetry — the operator would have had command execution capability on a server handling sensitive employee data, including personnel records, compensation information, and HR system credentials.

**What the evidence supports:**
- An unauthorized actor with administrative credentials attempted to access HR infrastructure — CONFIRMED
- The attempt failed on the first observed try — CONFIRMED
- Whether additional attempts occurred outside the log window — UNKNOWN

---

## Risk 2 — Plaintext Credential Exposure

**Rating: CRITICAL**
**Classification: CONFIRMED**

The PsExec command executed at 10:05:12 contained the `admin` account password as a plaintext `-p` argument:

```
psexec.exe \\SRV-APP-INT -u admin -p [REDACTED] cmd.exe
```

This credential was recorded in:
- Sysmon Event ID 1 (process creation with full command-line logging)
- Windows Security Event Log (Event ID 4688 if command-line auditing enabled)
- Elastic SIEM ingestion pipeline

The `admin` account credential is now a confirmed indicator of compromise. Any system where this credential is valid must be treated as potentially accessible to the same operator until the credential is rotated and all active sessions are terminated.

**Immediate implication:** The scope of the credential compromise is wider than this single incident. The `admin` account's access permissions across the domain determine the true blast radius, which cannot be assessed without Domain Controller data.

---

## Risk 3 — Lateral Movement to Unidentified Host (10.0.50.99)

**Rating: MEDIUM–HIGH**
**Classification: INFERRED**

An outbound RDP connection to `10.0.50.99` was permitted by the local firewall at 10:15:02. The identity, role, and sensitivity of this host are unknown from available telemetry.

The risk rating cannot be precisely determined without identifying the target host. Possibilities include:

| Scenario | Impact if True |
|---|---|
| Standard workstation | Medium — additional user account compromise |
| Internal server (file, application, database) | High — data access or persistence opportunity |
| Management or infrastructure host | Critical — potential for broader domain impact |

**The unknown identity of 10.0.50.99 is itself a risk indicator** — internal hosts in an enterprise environment should be identifiable from SIEM asset inventory. The absence of this host from observable records warrants investigation.

---

## Risk 4 — Internal Account Enumeration

**Rating: HIGH**
**Classification: CONFIRMED**

`WMIC useraccount get name,sid` was executed successfully on `WKSTN-MKT-04`, returning local account names and Security Identifiers. This information provides an operator with:

- A list of valid account names for credential stuffing or targeted phishing
- SID values usable for privilege escalation techniques (e.g., token manipulation, well-known SID abuse)
- Knowledge of service accounts or administrative accounts present on the host

The output of this command was not observed being transmitted or stored in available telemetry. Whether the enumerated data was used in subsequent actions — including the RDP/SMB attempts at 10:15 — is **UNKNOWN**.

---

## Risk 5 — Detection Gap: LotL Techniques Bypassing Endpoint Controls

**Rating: CRITICAL**
**Classification: CONFIRMED**

No endpoint protection alert fired during this incident. No malware was detected. The entire activity chain — PsExec execution, WMIC enumeration, firewall connection attempts — was completed using signed Microsoft binaries without triggering any automated response.

This is not a failure of the specific tools involved. It reflects a structural detection gap: **signature-based controls do not detect behavioral abuse of legitimate system utilities.**

The SOC identified this activity through manual analyst review of SIEM telemetry following a low-severity alert. In a higher-volume environment or during a period of alert fatigue, this activity could have continued undetected.

**Implication:** The absence of a detection alert cannot be interpreted as the absence of malicious activity in this environment.

---

## Affected Assets

| Asset | Role | Confirmed Impact | Potential Impact |
|---|---|---|---|
| WKSTN-MKT-04 (192.168.15.44) | Plant engineering workstation | Origin of all malicious activity | Session persistence unknown |
| m.perez account | Plant engineering user | Account used as attack origin | Full account scope unknown |
| admin account | Administrative account | Credential confirmed compromised (plaintext in logs) | Access scope across domain unknown |
| SRV-APP-INT (10.0.50.88) | HR application server | Targeted, authentication failed | Unknown if additional attempts succeeded |
| 10.0.50.99 | Unknown internal host | RDP connection permitted | Role and impact unknown |

---

## Out-of-Scope Findings Requiring Separate Assessment

The following were identified during log review but are not part of this incident. Their business risk cannot be assessed until a dedicated investigation is completed:

| Finding | Host | Risk Concern |
|---|---|---|
| `chrome.exe` running as `SYSTEM` from `C:\Windows\System32\` | SRV-DC-01 | Potential Domain Controller compromise — if confirmed, organization-wide impact |
| Administrative account accessing external APIs | IT workstation | Potential data exfiltration or C2 communication |
| RDP connections between unverified network segments | Multiple | Possible additional lateral movement campaign |

These findings should be prioritized for investigation given their potential severity, particularly the SRV-DC-01 anomaly.

---

## Related Documents

- [← Attack Hypothesis](04-attack-hypothesis.md)
- [Recommendations →](../remediation/recommendations.md)
- [IOC List →](../iocs/ioc-list.md)
